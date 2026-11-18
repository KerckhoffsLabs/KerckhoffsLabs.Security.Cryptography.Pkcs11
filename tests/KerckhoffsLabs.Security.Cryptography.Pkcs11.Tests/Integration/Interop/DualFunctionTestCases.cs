using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// CKM_AES_CBC_PAD is unauthenticated and refused by the default policy; these cases need a multi-part
// cipher whose output the BCL can reproduce, so they opt in, and the compile-time warning is suppressed
// for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>
/// Real-backend coverage for the dual-function calls (PKCS#11 v3.2 §5.13): <c>C_DigestEncryptUpdate</c>,
/// <c>C_DecryptDigestUpdate</c> and <c>C_DecryptVerifyUpdate</c>, until now run only against pkcs11-mock,
/// whose canned XOR transform proves the plumbing but not that a real token keeps two operations in step.
/// Every case checks both halves against the BCL: the digest is <see cref="SHA256.HashData(byte[])"/> of the
/// plaintext and the ciphertext is <see cref="Aes"/> CBC with PKCS#7 padding under the same key and IV, so a
/// token that fed one half the wrong bytes, dropped a partial block, or reset the IV between updates fails.
/// The buffer lengths include small ones, so the token sees many <c>*Update</c> calls: odd ones on the
/// encrypting side, whose pieces do not line up with the AES block, and whole blocks on the decrypting side,
/// since a token may refuse a CBC-PAD ciphertext part that is not a multiple of the block size (NSS does for
/// <c>C_DecryptUpdate</c>, Craton HSM for <c>C_DecryptDigestUpdate</c> and <c>C_DecryptVerifyUpdate</c>).
/// Gated by <see cref="IPkcs11Backend.SupportsDualFunctionCrypto"/>.
/// </summary>
internal static class DualFunctionTestCases
{
    private static readonly byte[] Iv = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");

    // Long enough to span many AES blocks and many pieces at the smaller buffer lengths, and not a multiple
    // of 16, so the final block is padded.
    private static readonly byte[] Plaintext = [.. Enumerable.Range(0, 1000).Select(i => unchecked((byte)(i * 7 + 3)))];

    private static void RequireDualFunction(IPkcs11Backend backend, params CKM[] mechanisms)
    {
        if (!backend.SupportsDualFunctionCrypto)
            Assert.Skip("Backend does not implement the dual-function calls.");
        backend.RequireMechanisms(mechanisms);
    }

    private static Mechanism CbcPad() => new(CKM.CKM_AES_CBC_PAD, Iv);

    private static byte[] BclEncrypt(byte[] key, byte[] plaintext)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        return aes.EncryptCbc(plaintext, Iv, PaddingMode.PKCS7);
    }

    private static void WithAesKey(IPkcs11Backend backend, Action<Pkcs11SessionCore, ObjectHandle, byte[]> body)
    {
        byte[] rawKey = RandomNumberGenerator.GetBytes(32);
        using var scope = TestKeys.OpenLoggedInSessionScope(backend);
        Pkcs11SessionCore session = scope.Session;
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
        try { body(session, key, rawKey); }
        finally { session.DestroyObject(key); }
    }

    internal static void Assert_DigestEncrypt_MatchesBclDigestAndCiphertext(IPkcs11Backend backend, int bufferLength)
    {
        RequireDualFunction(backend, CKM.CKM_SHA256, CKM.CKM_AES_CBC_PAD);

        WithAesKey(backend, (session, key, rawKey) =>
        {
            using var input = new MemoryStream(Plaintext);
            using var output = new MemoryStream();

            byte[] digest = session.DigestEncrypt(new Mechanism(CKM.CKM_SHA256), CbcPad(), key, input, output, bufferLength);

            Assert.Equal(SHA256.HashData(Plaintext), digest);
            Assert.Equal(BclEncrypt(rawKey, Plaintext), output.ToArray());
        });
    }

    internal static void Assert_DecryptDigest_MatchesBclPlaintextAndDigest(IPkcs11Backend backend, int bufferLength)
    {
        RequireDualFunction(backend, CKM.CKM_SHA256, CKM.CKM_AES_CBC_PAD);

        WithAesKey(backend, (session, key, rawKey) =>
        {
            using var input = new MemoryStream(BclEncrypt(rawKey, Plaintext));
            using var output = new MemoryStream();

            byte[] digest = session.DecryptDigest(new Mechanism(CKM.CKM_SHA256), CbcPad(), key, input, output, bufferLength);

            Assert.Equal(Plaintext, output.ToArray());
            Assert.Equal(SHA256.HashData(Plaintext), digest);
        });
    }

    /// <summary>
    /// A ciphertext part in the middle of a CBC-PAD decryption is not the end of the message, so whatever its
    /// plaintext ends with is data, not padding. The first block here ends in <c>01</c>, which is what one byte
    /// of PKCS#7 padding looks like, and the ciphertext goes to the token one block per
    /// <c>C_DecryptDigestUpdate</c>: a token that unpads every part drops that byte, and the digest with it.
    /// </summary>
    internal static void Assert_DecryptDigest_APartEndingLikePadding_KeepsEveryByte(IPkcs11Backend backend)
    {
        RequireDualFunction(backend, CKM.CKM_SHA256, CKM.CKM_AES_CBC_PAD);

        byte[] plaintext = [.. Enumerable.Repeat((byte)0xAA, 15), 0x01, .. Enumerable.Repeat((byte)0xBB, 20)];
        WithAesKey(backend, (session, key, rawKey) =>
        {
            using var input = new MemoryStream(BclEncrypt(rawKey, plaintext));
            using var output = new MemoryStream();

            byte[] digest = session.DecryptDigest(new Mechanism(CKM.CKM_SHA256), CbcPad(), key, input, output, 16);

            Assert.Equal(plaintext, output.ToArray());
            Assert.Equal(SHA256.HashData(plaintext), digest);
        });
    }

    internal static void Assert_DecryptVerify_AcceptsOnlyTheSignatureOfThePlaintext(IPkcs11Backend backend, int bufferLength)
    {
        RequireDualFunction(backend, CKM.CKM_AES_CBC_PAD, CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA_SHA256);

        WithAesKey(backend, (session, key, rawKey) =>
        {
            var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
            try
            {
                byte[] signature = session.Sign(new Mechanism(CKM.CKM_ECDSA_SHA256), priv, Plaintext);
                byte[] ciphertext = BclEncrypt(rawKey, Plaintext);

                bool valid = DecryptVerify(session, pub, key, ciphertext, signature, bufferLength, out byte[] decrypted);
                Assert.True(valid, "The signature of the plaintext did not verify through C_DecryptVerifyUpdate.");
                Assert.Equal(Plaintext, decrypted);

                byte[] altered = (byte[])signature.Clone();
                altered[^1] ^= 0x01;
                Assert.False(DecryptVerify(session, pub, key, ciphertext, altered, bufferLength, out decrypted),
                    "An altered signature verified through C_DecryptVerifyUpdate.");
                Assert.Equal(Plaintext, decrypted);
            }
            finally
            {
                session.DestroyObject(priv);
                session.DestroyObject(pub);
            }
        });
    }

    private static bool DecryptVerify(Pkcs11SessionCore session, ObjectHandle pub, ObjectHandle key, byte[] ciphertext,
        byte[] signature, int bufferLength, out byte[] decrypted)
    {
        using var input = new MemoryStream(ciphertext);
        using var output = new MemoryStream();
        bool valid = session.DecryptVerify(new Mechanism(CKM.CKM_ECDSA_SHA256), pub, CbcPad(), key, input, output, signature, bufferLength);
        decrypted = output.ToArray();
        return valid;
    }
}
