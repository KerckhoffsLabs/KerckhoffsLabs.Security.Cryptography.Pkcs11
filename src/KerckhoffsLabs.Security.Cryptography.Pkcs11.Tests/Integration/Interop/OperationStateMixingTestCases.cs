using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These tests drive the raw low-level dispatch directly, deliberately out of the sequence the
// PKCS#11 state machine requires (a single-part call while a multi-part operation is active, or a
// multi-part call after a single-part operation has already completed), so the compile-time warning
// is suppressed for this file only.
#pragma warning disable KLPKCS11008, KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>
/// Confirms each backend's actual behavior when a single-part call (<c>C_Digest</c>/<c>C_Sign</c>/
/// <c>C_Encrypt</c>/<c>C_Decrypt</c>) is made while the corresponding multi-part operation
/// (<c>...Init</c> + <c>...Update</c>) is still active, or when <c>...Update</c> is called after a
/// single-part operation has already completed.
/// </summary>
/// <remarks>
/// Prompted by AWS's "PKCS#11 Compliance Report for CloudHSM SDK 3.2.1" (Galois, Nov 2020), which
/// classifies this as "State Enforcement": CloudHSM's own library returns CKR_OK instead of
/// CKR_OPERATION_ACTIVE / an error for several of these cases, so "the library returns success
/// instead of an error [and] an application that does not comply with the specification will
/// experience silent loss of data." That report is specific to a backend this project does not
/// target, so it doesn't transfer directly, but it identified a genuine, previously-untested PKCS#11
/// state-machine property worth checking against our own backends.
/// <para>
/// Verified directly, not assumed (via the raw low-level dispatch, driving each session past the
/// point <c>Pkcs11Session</c>'s own high-level API would ever reach — it always completes an entire
/// operation, Init through Final, within a single method call, so this exact violation is not
/// reachable through this library's own public surface at all): NSS, SoftHSM2, and Kryoptic each
/// enforce SOME of these cases and not others, and none of the "not enforced" cases produce
/// nonsensical or silently-wrong output the way CloudHSM's own framing implies — in every case, the
/// backend consistently treats the illegal single-part call as an implicit continuation of the
/// active multi-part operation (i.e. as if it were another Update, immediately finalized), computing
/// a well-defined result over the full concatenation of everything fed to it. That's still a genuine
/// PKCS#11 state-machine non-compliance -- an application that (reasonably, per the spec) expects
/// CKR_OPERATION_ACTIVE here and doesn't check the return value would silently get a result over
/// more data than it intended -- just not the "nonsense data" failure mode CloudHSM describes.
/// </para>
/// <para>
/// Confirmed matrix (Digest-1/Sign-2/Encrypt-1: single-part call while multi-part is active;
/// Digest-2: Update after a completed single-part op; Decrypt-1: single-part call while multi-part
/// decrypt is active):
/// <list type="table">
/// <item><description>Digest-1: enforced on Kryoptic; NSS/SoftHSM2 treat it as a continuation.</description></item>
/// <item><description>Digest-2: enforced on all three.</description></item>
/// <item><description>Sign-2: enforced on SoftHSM2/Kryoptic; NSS treats it as a continuation.</description></item>
/// <item><description>Encrypt-1: NOT enforced on any of the three — all three treat it as a
/// continuation (CBC-PAD only emits whole ciphertext blocks as they become available and buffers
/// the remainder, so the single-part call's own output is a PREFIX of the full combined result
/// whenever the combined input doesn't land on a block boundary — not a different behavior, just
/// what "continuation, no Final follows" looks like for a block cipher).</description></item>
/// <item><description>Decrypt-1: enforced on all three (naturally, via a padding/tag mismatch
/// downstream of the malformed combined ciphertext — not because any of them checks operation state
/// here either).</description></item>
/// </list>
/// </para>
/// </remarks>
internal static class OperationStateMixingTestCases
{
    private static readonly byte[] Data1 = "part one "u8.ToArray();
    private static readonly byte[] Data2 = "part two "u8.ToArray();

    private static ObjectHandle CreateGenericSecret(Pkcs11Session session, byte[] rawKey)
    {
        using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var tok = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var s = new ObjectAttribute(CKA.CKA_SIGN, true);
        using var v = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var val = new ObjectAttribute(CKA.CKA_VALUE, rawKey);
        return session.CreateObject([c, t, tok, s, v, val]);
    }

    private static ObjectHandle CreateAes(Pkcs11Session session, byte[] rawKey)
    {
        using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var tok = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var e = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var d = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var val = new ObjectAttribute(CKA.CKA_VALUE, rawKey);
        return session.CreateObject([c, t, tok, e, d, val]);
    }

    private static CK_MECHANISM Marshal(MechanismParameterScope scope, Mechanism m) => m.Marshal(scope, out _);

    private static void AssertOk(CKR rv, string step) =>
        Assert.True(rv == CKR.CKR_OK, $"{step} was expected to succeed but returned {rv}.");

    private static byte[] CbcPadEncrypt(byte[] key, byte[] iv, byte[] data)
    {
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = System.Security.Cryptography.CipherMode.CBC;
        aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
        using var enc = aes.CreateEncryptor();
        return enc.TransformFinalBlock(data, 0, data.Length);
    }

    private static void WithRawSession(IPkcs11Backend backend, Action<LowLevelPkcs11Library, NativeCULong, Pkcs11Session> body)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            body(backend.Library.LowLevelLibrary!, (NativeCULong)session.SessionId, session);
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.Dispose(); }
    }

    // === Digest ==============================================================

    internal static void Assert_Digest_SinglePartAfterUpdate_Throws(IPkcs11Backend backend) =>
        WithRawSession(backend, (lowLevel, sid, session) =>
        {
            using (var scope = new MechanismParameterScope())
            {
                CK_MECHANISM mech = Marshal(scope, new Mechanism(CKM.CKM_SHA256));
                AssertOk(lowLevel.C_DigestInit(sid, ref mech), "DigestInit");
            }
            AssertOk(lowLevel.C_DigestUpdate(sid, Data1), "DigestUpdate");

            CKR rv = lowLevel.C_Digest(sid, Data2, new byte[64], lengthOnly: false, out NativeCULong _);
            Assert.NotEqual(CKR.CKR_OK, rv);

            // Ends the operation if it is still active. Its return code does not matter (the operation
            // may already have ended); a failure comes back as one, not as an exception.
            _ = lowLevel.C_DigestFinal(sid, new byte[64], lengthOnly: false, out NativeCULong _);
        });

    internal static void Assert_Digest_SinglePartAfterUpdate_TreatsAsContinuation(IPkcs11Backend backend) =>
        WithRawSession(backend, (lowLevel, sid, session) =>
        {
            using (var scope = new MechanismParameterScope())
            {
                CK_MECHANISM mech = Marshal(scope, new Mechanism(CKM.CKM_SHA256));
                AssertOk(lowLevel.C_DigestInit(sid, ref mech), "DigestInit");
            }
            AssertOk(lowLevel.C_DigestUpdate(sid, Data1), "DigestUpdate");

            byte[] buf = new byte[64];
            CKR rv = lowLevel.C_Digest(sid, Data2, buf, lengthOnly: false, out NativeCULong len);
            AssertOk(rv, "Digest (illegal single-part call)");

            byte[] got = buf.AsSpan(0, (int)len).ToArray();
            byte[] expected = System.Security.Cryptography.SHA256.HashData([.. Data1, .. Data2]);
            Assert.Equal(expected, got);

            // Ends the operation if it is still active. Its return code does not matter (the operation
            // may already have ended); a failure comes back as one, not as an exception.
            _ = lowLevel.C_DigestFinal(sid, new byte[64], lengthOnly: false, out NativeCULong _);
        });

    internal static void Assert_DigestUpdate_AfterCompletedDigest_Throws(IPkcs11Backend backend) =>
        WithRawSession(backend, (lowLevel, sid, _) =>
        {
            using (var scope = new MechanismParameterScope())
            {
                CK_MECHANISM mech = Marshal(scope, new Mechanism(CKM.CKM_SHA256));
                AssertOk(lowLevel.C_DigestInit(sid, ref mech), "DigestInit");
            }
            AssertOk(lowLevel.C_Digest(sid, Data1, new byte[64], lengthOnly: false, out NativeCULong _), "Digest");

            CKR rv = lowLevel.C_DigestUpdate(sid, Data2);
            Assert.NotEqual(CKR.CKR_OK, rv);
        });

    // === Sign =================================================================

    internal static void Assert_Sign_SinglePartAfterUpdate_Throws(IPkcs11Backend backend) =>
        WithRawSession(backend, (lowLevel, sid, session) =>
        {
            byte[] rawKey = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(rawKey);
            ObjectHandle key = CreateGenericSecret(session, rawKey);
            try
            {
                using (var scope = new MechanismParameterScope())
                {
                    CK_MECHANISM mech = Marshal(scope, new Mechanism(CKM.CKM_SHA256_HMAC));
                    AssertOk(lowLevel.C_SignInit(sid, ref mech, (NativeCULong)key.ObjectId), "SignInit");
                }
                AssertOk(lowLevel.C_SignUpdate(sid, Data1), "SignUpdate");

                CKR rv = lowLevel.C_Sign(sid, Data2, new byte[64], lengthOnly: false, out NativeCULong _);
                Assert.NotEqual(CKR.CKR_OK, rv);

                // Ends the operation if it is still active. Its return code does not matter (the operation
                // may already have ended); a failure comes back as one, not as an exception.
                _ = lowLevel.C_SignFinal(sid, new byte[64], lengthOnly: false, out NativeCULong _);
            }
            finally { session.DestroyObject(key); }
        });

    internal static void Assert_Sign_SinglePartAfterUpdate_TreatsAsContinuation(IPkcs11Backend backend) =>
        WithRawSession(backend, (lowLevel, sid, session) =>
        {
            byte[] rawKey = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(rawKey);
            ObjectHandle key = CreateGenericSecret(session, rawKey);
            try
            {
                using (var scope = new MechanismParameterScope())
                {
                    CK_MECHANISM mech = Marshal(scope, new Mechanism(CKM.CKM_SHA256_HMAC));
                    AssertOk(lowLevel.C_SignInit(sid, ref mech, (NativeCULong)key.ObjectId), "SignInit");
                }
                AssertOk(lowLevel.C_SignUpdate(sid, Data1), "SignUpdate");

                byte[] buf = new byte[64];
                CKR rv = lowLevel.C_Sign(sid, Data2, buf, lengthOnly: false, out NativeCULong len);
                AssertOk(rv, "Sign (illegal single-part call)");

                byte[] got = buf.AsSpan(0, (int)len).ToArray();
                using var hmac = new System.Security.Cryptography.HMACSHA256(rawKey);
                byte[] expected = hmac.ComputeHash([.. Data1, .. Data2]);
                Assert.Equal(expected, got);

                // Ends the operation if it is still active. Its return code does not matter (the operation
                // may already have ended); a failure comes back as one, not as an exception.
                _ = lowLevel.C_SignFinal(sid, new byte[64], lengthOnly: false, out NativeCULong _);
            }
            finally { session.DestroyObject(key); }
        });

    // === Encrypt / Decrypt ====================================================

    // Not enforced on any of the three real backends this project targets — see the class remarks.
    internal static void Assert_Encrypt_SinglePartAfterUpdate_TreatsAsContinuation(IPkcs11Backend backend) =>
        WithRawSession(backend, (lowLevel, sid, session) =>
        {
            byte[] rawKey = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(rawKey);
            byte[] iv = new byte[16];
            System.Security.Cryptography.RandomNumberGenerator.Fill(iv);
            ObjectHandle key = CreateAes(session, rawKey);
            try
            {
                using (var scope = new MechanismParameterScope())
                {
                    CK_MECHANISM mech = Marshal(scope, new Mechanism(CKM.CKM_AES_CBC_PAD, iv));
                    AssertOk(lowLevel.C_EncryptInit(sid, ref mech, (NativeCULong)key.ObjectId), "EncryptInit");
                }
                byte[] updBuf = new byte[64];
                AssertOk(lowLevel.C_EncryptUpdate(sid, Data1, updBuf, lengthOnly: false, out NativeCULong updLen), "EncryptUpdate");
                byte[] updOut = updBuf.AsSpan(0, (int)updLen).ToArray();

                byte[] encBuf = new byte[64];
                CKR rv = lowLevel.C_Encrypt(sid, Data2, encBuf, lengthOnly: false, out NativeCULong len);
                AssertOk(rv, "Encrypt (illegal single-part call)");
                byte[] got = encBuf.AsSpan(0, (int)len).ToArray();

                // A streaming cipher may only emit whole blocks as they become available and buffer
                // the remainder (no Final follows here), so the combined output so far is asserted
                // to be a PREFIX of the full combined-input ciphertext, not necessarily equal to it.
                byte[] combinedSoFar = [.. updOut, .. got];
                byte[] expectedFull = CbcPadEncrypt(rawKey, iv, [.. Data1, .. Data2]);
                Assert.True(combinedSoFar.Length <= expectedFull.Length,
                    "More ciphertext was emitted than AES-CBC-PAD(data1||data2) would ever produce.");
                Assert.Equal(expectedFull.AsSpan(0, combinedSoFar.Length).ToArray(), combinedSoFar);

                // Ends the operation if it is still active. Its return code does not matter (the operation
                // may already have ended); a failure comes back as one, not as an exception.
                _ = lowLevel.C_EncryptFinal(sid, new byte[64], lengthOnly: false, out NativeCULong _);
            }
            finally { session.DestroyObject(key); }
        });

    // Fixed, not random. Data1 encrypts to a single CBC-PAD block C1. A module that does not refuse the
    // single-part C_Decrypt after C_DecryptUpdate treats it as a continuation instead: it releases the
    // buffered block and decrypts C1 again, chained from C1, so its final block is AES-Dec(C1) XOR C1.
    // With random key material that block has valid PKCS#7 padding about 1 time in 256, the call then
    // returns CKR_OK, and the test failed intermittently on such a module. For this key and IV that block
    // ends in 0xBD — never valid padding — which PaddingOfAContinuationIsInvalid checks up front.
    private static readonly byte[] DecryptMixingKey = [.. Enumerable.Range(0x00, 32).Select(i => (byte)i)];
    private static readonly byte[] DecryptMixingIv = [.. Enumerable.Range(0xF0, 16).Select(i => (byte)i)];

    private static bool PaddingOfAContinuationIsInvalid(byte[] key, byte[] iv, byte[] data)
    {
        byte[] c1 = CbcPadEncrypt(key, iv, data);
        if (c1.Length != 16)
            return false; // the reasoning above assumes a single ciphertext block
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Key = key;
        byte[] block = aes.DecryptEcb(c1, System.Security.Cryptography.PaddingMode.None);
        for (int i = 0; i < block.Length; i++)
            block[i] ^= c1[i];
        int n = block[^1];
        return n is < 1 or > 16 || block.AsSpan(16 - n).ContainsAnyExcept((byte)n);
    }

    internal static void Assert_Decrypt_SinglePartAfterUpdate_Throws(IPkcs11Backend backend) =>
        WithRawSession(backend, (lowLevel, sid, session) =>
        {
            byte[] rawKey = DecryptMixingKey;
            byte[] iv = DecryptMixingIv;
            Assert.True(PaddingOfAContinuationIsInvalid(rawKey, iv, Data1),
                "The fixed key/IV no longer make a continuation's final block invalid padding; pick others.");
            ObjectHandle key = CreateAes(session, rawKey);
            try
            {
                // A real, whole, valid ciphertext -- produced via an ordinary ordered Init+Update+
                // Final sequence, so this setup step doesn't itself trip the check under test.
                byte[] validCiphertext;
                using (var scope = new MechanismParameterScope())
                {
                    CK_MECHANISM mech = Marshal(scope, new Mechanism(CKM.CKM_AES_CBC_PAD, iv));
                    AssertOk(lowLevel.C_EncryptInit(sid, ref mech, (NativeCULong)key.ObjectId), "EncryptInit(setup)");
                }
                byte[] part1 = new byte[64];
                AssertOk(lowLevel.C_EncryptUpdate(sid, Data1, part1, lengthOnly: false, out NativeCULong part1Len), "EncryptUpdate(setup)");
                byte[] part2 = new byte[64];
                AssertOk(lowLevel.C_EncryptFinal(sid, part2, lengthOnly: false, out NativeCULong part2Len), "EncryptFinal(setup)");
                validCiphertext = [.. part1.AsSpan(0, (int)part1Len), .. part2.AsSpan(0, (int)part2Len)];

                using (var scope = new MechanismParameterScope())
                {
                    CK_MECHANISM mech = Marshal(scope, new Mechanism(CKM.CKM_AES_CBC_PAD, iv));
                    AssertOk(lowLevel.C_DecryptInit(sid, ref mech, (NativeCULong)key.ObjectId), "DecryptInit");
                }
                AssertOk(lowLevel.C_DecryptUpdate(sid, validCiphertext.AsSpan(0, 16), new byte[64], lengthOnly: false, out NativeCULong _), "DecryptUpdate");

                CKR rv = lowLevel.C_Decrypt(sid, validCiphertext, new byte[64], lengthOnly: false, out NativeCULong _);
                Assert.NotEqual(CKR.CKR_OK, rv);

                // Ends the operation if it is still active. Its return code does not matter (the operation
                // may already have ended); a failure comes back as one, not as an exception.
                _ = lowLevel.C_DecryptFinal(sid, new byte[64], lengthOnly: false, out NativeCULong _);
            }
            finally { session.DestroyObject(key); }
        });
}
