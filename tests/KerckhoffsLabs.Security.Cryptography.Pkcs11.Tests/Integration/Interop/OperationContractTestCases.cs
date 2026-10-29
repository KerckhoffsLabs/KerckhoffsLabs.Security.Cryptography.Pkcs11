using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// The CBC cases opt in to CKM_AES_CBC and CKM_AES_CBC_PAD on the session (UsePolicy), which the
// compile-time policy analyzer cannot see, so its warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>
/// The parts of the PKCS#11 operation contract this library builds on, checked on every real backend: the
/// two-call length convention and <c>CKR_BUFFER_TOO_SMALL</c> (§5.2), the multi-part paths the session's
/// stream overloads drive, and the operation ending on an error so that the next <c>C_*Init</c> succeeds.
/// </summary>
/// <remarks>
/// Each case is a regression test for a class of module bug found and fixed in a real token: a
/// <c>C_DecryptFinal</c> that reported a zero length and then wrote the CBC-PAD tail into the caller's
/// empty buffer; a short-buffer <c>C_Sign</c> that answered <c>CKR_FUNCTION_FAILED</c> and lost the
/// operation; operations left active after a refused <c>C_VerifyFinal</c> or a failed decryption, so the next
/// Init answered <c>CKR_OPERATION_ACTIVE</c>; and multi-part digests and MACs that hard-coded one hash or
/// failed at <c>C_*Update</c>. The public adapters buffer and make one single-part call, so these paths are
/// reached through <see cref="Pkcs11SessionCore"/>'s stream overloads or the raw dispatch.
/// </remarks>
internal static class OperationContractTestCases
{
    private static readonly byte[] Message = "the quick brown fox jumps over the lazy dog, twice over."u8.ToArray();

    private static CK_MECHANISM Marshal(MechanismParameterScope scope, Mechanism m) => m.Marshal(scope, out _);

    private static void AssertOk(CKR rv, string step) =>
        Assert.True(rv == CKR.CKR_OK, $"{step} was expected to succeed but returned {rv}.");

    private static void WithSession(IPkcs11Backend backend, Action<LowLevelPkcs11Library, NativeCULong, Pkcs11SessionCore> body)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            body(backend.Library.LowLevelLibrary!, (NativeCULong)session.SessionId, session);
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    private delegate CKR KeyedInit(NativeCULong session, in CK_MECHANISM mechanism, NativeCULong key);

    private static CKR Init(KeyedInit init, NativeCULong sid, Mechanism mechanism, ObjectHandle key)
    {
        using var scope = new MechanismParameterScope();
        CK_MECHANISM mech = Marshal(scope, mechanism);
        return init(sid, in mech, (NativeCULong)key.ObjectId);
    }

    private static CKR DigestInit(LowLevelPkcs11Library lowLevel, NativeCULong sid, CKM mechanism)
    {
        using var scope = new MechanismParameterScope();
        CK_MECHANISM mech = Marshal(scope, new Mechanism(mechanism));
        return lowLevel.C_DigestInit(sid, in mech);
    }

    // === Multi-part CBC-PAD decryption ======================================

    // C_DecryptFinal carries the plaintext tail CBC-PAD holds back. The stream overload asks for its length
    // and allocates what was reported, the call pattern that overflowed a module answering 0 to the query.
    internal static void Assert_CbcPad_MultipartDecrypt_MatchesBcl(IPkcs11Backend backend)
    {
        backend.RequireMechanismFlags(CKM.CKM_AES_CBC_PAD, f => f.Decrypt, "CKF_DECRYPT");
        WithSession(backend, (lowLevel, sid, session) =>
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            byte[] rawKey = RandomNumberGenerator.GetBytes(32);
            ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
            try
            {
                using var aes = Aes.Create();
                aes.Key = rawKey;
                foreach (int length in (int[])[1, 15, 16, 17, 31, 33])
                {
                    byte[] plaintext = Message.AsSpan(0, length).ToArray();
                    byte[] iv = RandomNumberGenerator.GetBytes(16);
                    byte[] ciphertext = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
                    var mechanism = new Mechanism(CKM.CKM_AES_CBC_PAD, iv);

                    // Whole blocks per C_DecryptUpdate: NSS refuses a CBC-PAD part that is not a multiple of
                    // the block size with CKR_ENCRYPTED_DATA_LEN_RANGE.
                    foreach (int bufferLength in (int[])[16, 32, 48, 64])
                    {
                        using var input = new MemoryStream(ciphertext);
                        using var output = new MemoryStream();
                        session.Decrypt(mechanism, key, input, output, bufferLength);
                        Assert.True(plaintext.AsSpan().SequenceEqual(output.ToArray()),
                            $"{length}-byte plaintext decrypted in {bufferLength}-byte pieces");
                    }

                    // Raw: every block through C_DecryptUpdate, then the length query and the tail.
                    AssertOk(Init(lowLevel.C_DecryptInit, sid, mechanism, key), "DecryptInit");
                    byte[] part = new byte[ciphertext.Length];
                    AssertOk(lowLevel.C_DecryptUpdate(sid, ciphertext, part, lengthOnly: false, out NativeCULong partLen), "DecryptUpdate");
                    AssertOk(lowLevel.C_DecryptFinal(sid, [], lengthOnly: true, out NativeCULong reported), "DecryptFinal (length query)");
                    int tail = length - (int)partLen;
                    Assert.True((int)reported >= tail, $"C_DecryptFinal reported {reported} bytes for a {tail}-byte tail.");
                    byte[] last = new byte[(int)reported];
                    AssertOk(lowLevel.C_DecryptFinal(sid, last, lengthOnly: false, out NativeCULong lastLen), "DecryptFinal");
                    byte[] whole = [.. part.AsSpan(0, (int)partLen), .. last.AsSpan(0, (int)lastLen)];
                    Assert.Equal(plaintext, whole);
                }
            }
            finally { session.DestroyObject(key); }
        });
    }

    // === CKR_BUFFER_TOO_SMALL ================================================

    public static TheoryData<string> BufferTooSmallOperations => ["ECDSA-P256", "RSA-PSS-SHA256", "RSA-OAEP-SHA256", "Ed25519", "Ed448", "ML-DSA-44"];

    // A single-part call with a 1-byte buffer must answer CKR_BUFFER_TOO_SMALL (§5.2), report a length the
    // caller can act on, and keep the operation for the retry. Two recorded deviations are tolerated, as the
    // library tolerates them: a module that reports no length (leaves the caller's in place, as opencryptoki
    // does, or answers 0, as NSS does), so that the caller asks again, and one that ends the operation on the
    // error (NSS), so that the caller starts it again. Anything else, CKR_FUNCTION_FAILED included, fails.
    internal static void Assert_SingleCall_BufferTooSmall_ReportsAUsableLength(IPkcs11Backend backend, string operation)
    {
        CKM[] needed = operation switch
        {
            "ECDSA-P256" => [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA],
            "RSA-PSS-SHA256" => [CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS_PSS],
            "Ed25519" or "Ed448" => [CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM.CKM_EDDSA],
            "ML-DSA-44" => [CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_ML_DSA],
            _ => [CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_PKCS_OAEP],
        };
        backend.RequireMechanisms(needed);

        WithSession(backend, (lowLevel, sid, session) =>
        {
            byte[] digest = SHA256.HashData(Message);
            switch (operation)
            {
                case "ECDSA-P256":
                    {
                        var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
                        try
                        {
                            var mechanism = new Mechanism(CKM.CKM_ECDSA);
                            byte[] signature = SignWithAShortBufferFirst(lowLevel, sid, mechanism, priv, digest, 64);
                            Assert.True(session.Verify(mechanism, pub, digest, signature));
                        }
                        finally { session.DestroyObject(priv); session.DestroyObject(pub); }
                        break;
                    }
                case "Ed25519":
                case "Ed448":
                    {
                        var (pub, priv) = operation == "Ed25519" ? TestKeys.GenerateEd25519KeyPair(session) : TestKeys.GenerateEd448KeyPair(session);
                        try
                        {
                            // A bare CKM_EDDSA is not taken for Ed448 everywhere; the pure-EdDSA parameters are.
                            var mechanism = operation == "Ed25519" ? new Mechanism(CKM.CKM_EDDSA) : new Mechanism(CKM.CKM_EDDSA, new CkmEddsaParams(phFlag: false));
                            byte[] signature = SignWithAShortBufferFirst(lowLevel, sid, mechanism, priv, Message, operation == "Ed25519" ? 64 : 114);
                            Assert.True(session.Verify(mechanism, pub, Message, signature));
                        }
                        finally { session.DestroyObject(priv); session.DestroyObject(pub); }
                        break;
                    }
                case "ML-DSA-44":
                    {
                        var (pub, priv) = TestKeys.GenerateMlDsaKeyPair(session, CkpMlDsa.CKP_ML_DSA_44);
                        try
                        {
                            var mechanism = new Mechanism(CKM.CKM_ML_DSA);
                            byte[] signature = SignWithAShortBufferFirst(lowLevel, sid, mechanism, priv, Message, 2420);
                            Assert.True(session.Verify(mechanism, pub, Message, signature));
                        }
                        finally { session.DestroyObject(priv); session.DestroyObject(pub); }
                        break;
                    }
                case "RSA-PSS-SHA256":
                    {
                        var (pub, priv) = TestKeys.GenerateRsa2048SigningKeyPair(session);
                        try
                        {
                            var mechanism = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));
                            byte[] signature = SignWithAShortBufferFirst(lowLevel, sid, mechanism, priv, Message, 256);
                            Assert.True(session.Verify(mechanism, pub, Message, signature));
                        }
                        finally { session.DestroyObject(priv); session.DestroyObject(pub); }
                        break;
                    }
                default:
                    {
                        var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
                        try
                        {
                            var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256));
                            byte[] plaintext = Message.AsSpan(0, 29).ToArray();
                            byte[] ciphertext = OrSkipIfOaepHashUnsupported(() => session.Encrypt(mechanism, pub, plaintext));
                            byte[] recovered = RunWithAShortBufferFirst(
                                () => Init(lowLevel.C_DecryptInit, sid, mechanism, priv),
                                (buffer, lengthOnly) => (lowLevel.C_Decrypt(sid, ciphertext, buffer, lengthOnly, out NativeCULong n), n),
                                plaintext.Length);
                            Assert.Equal(plaintext, recovered);
                        }
                        finally { session.DestroyObject(priv); session.DestroyObject(pub); }
                        break;
                    }
            }
        });
    }

    private static byte[] SignWithAShortBufferFirst(
        LowLevelPkcs11Library lowLevel, NativeCULong sid, Mechanism mechanism, ObjectHandle key, byte[] data, int length) =>
        RunWithAShortBufferFirst(
            () => Init(lowLevel.C_SignInit, sid, mechanism, key),
            (buffer, lengthOnly) => (lowLevel.C_Sign(sid, data, buffer, lengthOnly, out NativeCULong n), n),
            length);

    private delegate (CKR rv, NativeCULong length) SingleCall(Span<byte> buffer, bool lengthOnly);

    private static byte[] RunWithAShortBufferFirst(Func<CKR> init, SingleCall call, int length)
    {
        AssertOk(init(), "Init");
        byte[] tiny = new byte[1];
        var (rv, reported) = call(tiny, false);
        Assert.True(rv == CKR.CKR_BUFFER_TOO_SMALL, $"A 1-byte buffer for a {length}-byte result returned {rv}.");
        Assert.True((ulong)reported >= (ulong)length || (ulong)reported <= (ulong)tiny.Length,
            $"CKR_BUFFER_TOO_SMALL reported {reported} bytes for a {length}-byte result.");

        if ((ulong)reported <= (ulong)tiny.Length)
        {
            // No length reported: ask for it, as the library does.
            (rv, reported) = CallAgain(init, () => call([], true));
            AssertOk(rv, "the length query");
        }
        byte[] buffer = new byte[Math.Max((int)(ulong)reported, length)];
        (rv, NativeCULong written) = CallAgain(init, () => call(buffer, false));
        AssertOk(rv, $"the call with a {buffer.Length}-byte buffer (CKR_BUFFER_TOO_SMALL reported {reported})");
        return buffer.AsSpan(0, (int)written).ToArray();
    }

    // A module that ended the operation on CKR_BUFFER_TOO_SMALL answers the next call with
    // CKR_OPERATION_NOT_INITIALIZED; the operation is started again for it.
    private static (CKR rv, NativeCULong length) CallAgain(Func<CKR> init, Func<(CKR rv, NativeCULong length)> call)
    {
        var result = call();
        if (result.rv != CKR.CKR_OPERATION_NOT_INITIALIZED)
            return result;
        AssertOk(init(), "Init (again)");
        return call();
    }

    // === The session after an error ==========================================

    public static TheoryData<string> FailingOperations => ["AES-CBC partial block", "HMAC wrong MAC", "RSA-OAEP tampered"];

    // An operation that fails part-way leaves the session usable: the same kind of operation then succeeds
    // on it. PKCS#11 has the error end the operation (§5.2); where a module keeps it active, the library
    // cancels it with C_SessionCancel. A module that kept it active and could not cancel it failed the next
    // C_*Init with CKR_OPERATION_ACTIVE.
    internal static void Assert_Operation_AfterAnError_TheSessionStaysUsable(IPkcs11Backend backend, string failure)
    {
        CKM[] needed = failure switch
        {
            "AES-CBC partial block" => [CKM.CKM_AES_CBC],
            "HMAC wrong MAC" => [CKM.CKM_SHA256_HMAC],
            _ => [CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_PKCS_OAEP],
        };
        backend.RequireMechanisms(needed);

        WithSession(backend, (_, _, session) =>
        {
            switch (failure)
            {
                case "AES-CBC partial block":
                    {
                        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
                        byte[] rawKey = RandomNumberGenerator.GetBytes(32);
                        byte[] iv = RandomNumberGenerator.GetBytes(16);
                        ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
                        try
                        {
                            var mechanism = new Mechanism(CKM.CKM_AES_CBC, iv);
                            // One and a half blocks: C_DecryptFinal (or the update) refuses the partial block.
                            using (var input = new MemoryStream(new byte[24]))
                            using (var output = new MemoryStream())
                                Assert.ThrowsAny<CryptographicException>(() => session.Decrypt(mechanism, key, input, output, bufferLength: 16));

                            using var aes = Aes.Create();
                            aes.Key = rawKey;
                            byte[] block = RandomNumberGenerator.GetBytes(16);
                            Assert.Equal(block, session.Decrypt(mechanism, key, aes.EncryptCbc(block, iv, PaddingMode.None)));
                        }
                        finally { session.DestroyObject(key); }
                        break;
                    }
                case "HMAC wrong MAC":
                    {
                        byte[] rawKey = RandomNumberGenerator.GetBytes(32);
                        ObjectHandle key = TestKeys.CreateGenericSecretKey(session, rawKey);
                        try
                        {
                            var mechanism = new Mechanism(CKM.CKM_SHA256_HMAC);
                            byte[] mac = HMACSHA256.HashData(rawKey, Message);
                            byte[] wrong = (byte[])mac.Clone();
                            wrong[0] ^= 0x01;

                            using (var input = new MemoryStream(Message))
                                Assert.False(session.Verify(mechanism, key, input, wrong, bufferLength: 7));
                            using (var input = new MemoryStream(Message))
                                Assert.True(session.Verify(mechanism, key, input, mac, bufferLength: 7));
                        }
                        finally { session.DestroyObject(key); }
                        break;
                    }
                default:
                    {
                        var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
                        try
                        {
                            var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256));
                            byte[] ciphertext = OrSkipIfOaepHashUnsupported(() => session.Encrypt(mechanism, pub, Message));
                            byte[] tampered = (byte[])ciphertext.Clone();
                            tampered[^1] ^= 0x01;

                            Assert.ThrowsAny<CryptographicException>(() => session.Decrypt(mechanism, priv, tampered));
                            Assert.Equal(Message, session.Decrypt(mechanism, priv, ciphertext));
                        }
                        finally { session.DestroyObject(priv); session.DestroyObject(pub); }
                        break;
                    }
            }
        });
    }

    // A session closed in the middle of an operation leaves nothing behind for the next session, even when
    // the module hands out the same session handle again.
    internal static void Assert_Session_ClosedMidOperation_LeavesTheNextSessionClean(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256);
        WithSession(backend, (lowLevel, sid, _) =>
        {
            AssertOk(DigestInit(lowLevel, sid, CKM.CKM_SHA256), "DigestInit");
            AssertOk(lowLevel.C_DigestUpdate(sid, Message), "DigestUpdate");
        });
        WithSession(backend, (lowLevel, sid, _) =>
        {
            AssertOk(DigestInit(lowLevel, sid, CKM.CKM_SHA256), "DigestInit in the next session");
            byte[] buffer = new byte[32];
            AssertOk(lowLevel.C_Digest(sid, Message, buffer, lengthOnly: false, out NativeCULong n), "Digest");
            Assert.Equal(SHA256.HashData(Message), buffer.AsSpan(0, (int)n).ToArray());
        });
    }

    // === Unpadded block modes through the stream overloads ====================

    public static TheoryData<CKM> UnpaddedStreamModes => [CKM.CKM_AES_CBC, CKM.CKM_AES_ECB];

    // A block mode without padding writes every block as its update consumes it, so its final has nothing
    // to write. The stream overloads still ask the final for its length; a module whose length query ends
    // the operation then has the final answer CKR_OPERATION_NOT_INITIALIZED, which completes the stream
    // rather than failing it. Whole-block pieces, so that every module takes each update.
    internal static void Assert_UnpaddedBlockMode_StreamRoundTrip_MatchesBcl(IPkcs11Backend backend, CKM mode)
    {
        backend.RequireMechanismFlags(mode, f => f.Encrypt && f.Decrypt, "CKF_ENCRYPT and CKF_DECRYPT");
        WithSession(backend, (_, _, session) =>
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            byte[] rawKey = RandomNumberGenerator.GetBytes(32);
            ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
            try
            {
                using var aes = Aes.Create();
                aes.Key = rawKey;
                foreach (int length in (int[])[16, 48, 4112])
                {
                    byte[] plaintext = RandomNumberGenerator.GetBytes(length);
                    foreach (int bufferLength in (int[])[16, 48, 4096])
                    {
                        // A fresh IV for every encryption: Craton HSM refuses to encrypt twice under one key and IV.
                        byte[] iv = RandomNumberGenerator.GetBytes(16);
                        var mechanism = mode == CKM.CKM_AES_CBC ? new Mechanism(mode, iv) : new Mechanism(mode);
                        byte[] expected = mode == CKM.CKM_AES_CBC ? aes.EncryptCbc(plaintext, iv, PaddingMode.None) : aes.EncryptEcb(plaintext, PaddingMode.None);

                        using var encrypted = new MemoryStream();
                        using (var input = new MemoryStream(plaintext))
                            session.Encrypt(mechanism, key, input, encrypted, bufferLength);
                        Assert.True(expected.AsSpan().SequenceEqual(encrypted.ToArray()), $"{length} bytes encrypted in {bufferLength}-byte pieces");

                        using var decrypted = new MemoryStream();
                        using (var input = new MemoryStream(expected))
                            session.Decrypt(mechanism, key, input, decrypted, bufferLength);
                        Assert.True(plaintext.AsSpan().SequenceEqual(decrypted.ToArray()), $"{length} bytes decrypted in {bufferLength}-byte pieces");
                    }
                }
            }
            finally { session.DestroyObject(key); }
        });
    }

    // === Multi-part digests and MACs =========================================

    public static TheoryData<CKM> MultipartDigests =>
    [
        CKM.CKM_SHA224, CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512, CKM.CKM_SHA512_224, CKM.CKM_SHA512_256,
        CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512,
    ];

    // C_DigestUpdate in 7-byte pieces equals the single-part C_Digest, for every digest the token lists.
    internal static void Assert_Digest_Multipart_MatchesSinglePart(IPkcs11Backend backend, CKM mechanism)
    {
        backend.RequireMechanism(mechanism);
        WithSession(backend, (_, _, session) =>
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            var m = new Mechanism(mechanism);
            byte[] oneShot = session.Digest(m, Message);
            using var input = new MemoryStream(Message);
            Assert.Equal(oneShot, session.Digest(m, input, bufferLength: 7));

            byte[]? reference = mechanism switch
            {
                CKM.CKM_SHA256 => SHA256.HashData(Message),
                CKM.CKM_SHA384 => SHA384.HashData(Message),
                CKM.CKM_SHA512 => SHA512.HashData(Message),
                CKM.CKM_SHA3_256 when SHA3_256.IsSupported => SHA3_256.HashData(Message),
                CKM.CKM_SHA3_384 when SHA3_384.IsSupported => SHA3_384.HashData(Message),
                CKM.CKM_SHA3_512 when SHA3_512.IsSupported => SHA3_512.HashData(Message),
                _ => null,
            };
            if (reference is not null)
                Assert.Equal(reference, oneShot);
        });
    }

    public static TheoryData<CKM> MultipartHmacs => [CKM.CKM_SHA256_HMAC, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC, CKM.CKM_SHA3_256_HMAC];

    // C_SignUpdate x3 + C_SignFinal, and the stream verify, against the BCL's HMAC.
    internal static void Assert_Hmac_Multipart_MatchesBcl(IPkcs11Backend backend, CKM mechanism)
    {
        backend.RequireMechanism(mechanism);
        if (mechanism == CKM.CKM_SHA3_256_HMAC && !HMACSHA3_256.IsSupported)
            Assert.Skip("The platform has no HMAC-SHA3-256 to compare with.");

        WithSession(backend, (lowLevel, sid, session) =>
        {
            // As long as the MAC: SoftHSM refuses a shorter HMAC key with CKR_KEY_SIZE_RANGE.
            byte[] rawKey = RandomNumberGenerator.GetBytes(mechanism switch
            {
                CKM.CKM_SHA384_HMAC => 48,
                CKM.CKM_SHA512_HMAC => 64,
                _ => 32,
            });
            byte[] expected = mechanism switch
            {
                CKM.CKM_SHA256_HMAC => HMACSHA256.HashData(rawKey, Message),
                CKM.CKM_SHA384_HMAC => HMACSHA384.HashData(rawKey, Message),
                CKM.CKM_SHA512_HMAC => HMACSHA512.HashData(rawKey, Message),
                _ => HMACSHA3_256.HashData(rawKey, Message),
            };
            ObjectHandle key = TestKeys.CreateGenericSecretKey(session, rawKey);
            try
            {
                var m = new Mechanism(mechanism);
                AssertOk(Init(lowLevel.C_SignInit, sid, m, key), "SignInit");
                AssertOk(lowLevel.C_SignUpdate(sid, Message.AsSpan(0, 5)), "SignUpdate 1");
                AssertOk(lowLevel.C_SignUpdate(sid, Message.AsSpan(5, 20)), "SignUpdate 2");
                AssertOk(lowLevel.C_SignUpdate(sid, Message.AsSpan(25)), "SignUpdate 3");
                byte[] mac = new byte[64];
                AssertOk(lowLevel.C_SignFinal(sid, mac, lengthOnly: false, out NativeCULong n), "SignFinal");
                Assert.Equal(expected, mac.AsSpan(0, (int)n).ToArray());

                using var input = new MemoryStream(Message);
                Assert.True(session.Verify(m, key, input, expected, bufferLength: 7));
            }
            finally { session.DestroyObject(key); }
        });
    }

    // SoftHSM 2.5 (the softhsm-v240 CI leg's pinned Debian binary) advertises CKM_RSA_PKCS_OAEP but only
    // accepts CKM_SHA_1 as the hash parameter: SHA-256 fails at C_EncryptInit with CKR_ARGUMENTS_BAD.
    // Mirrors RSAPkcs11TestCases.OrSkipIfOaepHashUnsupported's convention for this limitation.
    private static byte[] OrSkipIfOaepHashUnsupported(Func<byte[]> op)
    {
        try
        {
            return op();
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue is
            CKR.CKR_MECHANISM_PARAM_INVALID or CKR.CKR_MECHANISM_INVALID or
            CKR.CKR_ARGUMENTS_BAD or CKR.CKR_FUNCTION_NOT_SUPPORTED)
        {
            Assert.Skip("Token advertises OAEP but rejects this hash parameter.");
            throw; // Assert.Skip always throws; xunit.v3.assert 4.0.1 lacks [DoesNotReturn].
        }
    }
}
