using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic AesGcmPkcs11 tests: argument validation, AEAD round-trips (with/without AAD,
/// various tag sizes), authenticity negatives, and a published known-answer vector. Operations skip
/// where the backend does not advertise <c>CKM_AES_GCM</c>. Authentication-failure cases assert a
/// <see cref="Pkcs11Exception"/> (forgery rejected, not a crash) rather than an exact CKR, since that
/// code varies by backend (SoftHSM: CKR_ENCRYPTED_DATA_INVALID; opencryptoki may differ).
/// </summary>
internal static class AesGcmPkcs11TestCases
{
    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static byte[] Iota(int length)
    {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) b[i] = (byte)i;
        return b;
    }

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    // Generates an ephemeral AES-256 key, wraps it as AesGcmPkcs11, runs the body, then destroys it.
    // Skips when the backend does not advertise CKM_AES_GCM.
    private static void WithGcm(IPkcs11Backend backend, Action<AesGcmPkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_AES_GCM))
            throw new SkipTestException("Backend does not advertise CKM_AES_GCM.");

        using var workspace = OpenWorkspace(backend);
        string label = $"gcm-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var gcm = new AesGcmPkcs11(key);
            body(gcm);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // Imports a known AES key (by value) so a deterministic vector can be checked.
    private static void WithImportedGcm(IPkcs11Backend backend, byte[] rawKey, Action<AesGcmPkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_AES_GCM))
            throw new SkipTestException("Backend does not advertise CKM_AES_GCM.");

        using var workspace = OpenWorkspace(backend);
        string label = $"gcm-kat-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(rawKey).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var gcm = new AesGcmPkcs11(key);
            body(gcm);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Construction =====================================================

    internal static void Assert_Ctor_NonAesKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"gcm-nonaes-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(32).Sign().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new AesGcmPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Argument validation ==============================================

    internal static void Assert_Encrypt_InvalidNonceLength_Throws(IPkcs11Backend backend, int nonceLength) =>
        WithGcm(backend, gcm =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                gcm.Encrypt(new byte[nonceLength], new byte[8], new byte[8], new byte[16]));
            Assert.Equal("nonce", ex.ParamName);
        });

    internal static void Assert_Decrypt_InvalidNonceLength_Throws(IPkcs11Backend backend, int nonceLength) =>
        WithGcm(backend, gcm =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                gcm.Decrypt(new byte[nonceLength], new byte[8], new byte[16], new byte[8]));
            Assert.Equal("nonce", ex.ParamName);
        });

    internal static void Assert_Encrypt_InvalidTagLength_Throws(IPkcs11Backend backend, int tagLength) =>
        WithGcm(backend, gcm =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                gcm.Encrypt(new byte[12], new byte[8], new byte[8], new byte[tagLength]));
            Assert.Equal("tagLength", ex.ParamName);
        });

    internal static void Assert_Decrypt_InvalidTagLength_Throws(IPkcs11Backend backend, int tagLength) =>
        WithGcm(backend, gcm =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                gcm.Decrypt(new byte[12], new byte[8], new byte[tagLength], new byte[8]));
            Assert.Equal("tagLength", ex.ParamName);
        });

    internal static void Assert_Encrypt_CiphertextLengthMismatch_Throws(IPkcs11Backend backend) =>
        WithGcm(backend, gcm =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                gcm.Encrypt(new byte[12], new byte[8], new byte[7], new byte[16]));
            Assert.Equal("ciphertext", ex.ParamName);
        });

    internal static void Assert_Decrypt_PlaintextLengthMismatch_Throws(IPkcs11Backend backend) =>
        WithGcm(backend, gcm =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                gcm.Decrypt(new byte[12], new byte[8], new byte[16], new byte[7]));
            Assert.Equal("plaintext", ex.ParamName);
        });

    internal static void Assert_Encrypt_AfterDispose_Throws(IPkcs11Backend backend) =>
        WithGcm(backend, gcm =>
        {
            gcm.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                gcm.Encrypt(new byte[12], new byte[8], new byte[8], new byte[16]));
        });

    internal static void Assert_Decrypt_AfterDispose_Throws(IPkcs11Backend backend) =>
        WithGcm(backend, gcm =>
        {
            gcm.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                gcm.Decrypt(new byte[12], new byte[8], new byte[16], new byte[8]));
        });

    // === Round-trips ======================================================

    internal static void Assert_EncryptDecrypt_RoundTrips_WithAad(IPkcs11Backend backend) =>
        WithGcm(backend, gcm =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("AES-GCM round trip");
            byte[] aad = Encoding.UTF8.GetBytes("associated-data");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            byte[] decrypted = new byte[plaintext.Length];
            gcm.Decrypt(nonce, ciphertext, tag, decrypted, aad);

            Assert.Equal(plaintext, decrypted);
            Assert.NotEqual(plaintext, ciphertext); // sanity: data was actually transformed
        });

    internal static void Assert_EncryptDecrypt_RoundTrips_NoAad(IPkcs11Backend backend) =>
        WithGcm(backend, gcm =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("no associated data");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            gcm.Encrypt(nonce, plaintext, ciphertext, tag);
            byte[] decrypted = new byte[plaintext.Length];
            gcm.Decrypt(nonce, ciphertext, tag, decrypted);

            Assert.Equal(plaintext, decrypted);
        });

    internal static void Assert_EncryptDecrypt_RoundTrips_VariousTagSizes(IPkcs11Backend backend, int tagLen) =>
        WithGcm(backend, gcm =>
        {
            // AesGcmPkcs11.TagByteSizes mirrors the BCL AesGcm, which on macOS is 16..16 — so sub-16
            // tags are unsupported there regardless of the token. Skip those rather than fail.
            if (tagLen < AesGcm.TagByteSizes.MinSize)
                throw new SkipTestException($"Platform AesGcm minimum tag size is {AesGcm.TagByteSizes.MinSize} bytes.");

            byte[] nonce = Iota(12);
            byte[] plaintext = Iota(40);
            byte[] aad = Iota(13);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[tagLen];

            gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            byte[] decrypted = new byte[plaintext.Length];
            gcm.Decrypt(nonce, ciphertext, tag, decrypted, aad);

            Assert.Equal(plaintext, decrypted);
        });

    // === Authenticity negatives ===========================================

    internal static void Assert_Decrypt_TamperedTag_Throws(IPkcs11Backend backend) =>
        WithGcm(backend, gcm =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("authenticity");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            gcm.Encrypt(nonce, plaintext, ciphertext, tag);
            tag[0] ^= 0xFF;

            byte[] dest = new byte[plaintext.Length];
            AeadTestSupport.AssertAuthFailure(backend, () => gcm.Decrypt(nonce, ciphertext, tag, dest));
        });

    internal static void Assert_Decrypt_TamperedCiphertext_Throws(IPkcs11Backend backend) =>
        WithGcm(backend, gcm =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("integrity matters");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            gcm.Encrypt(nonce, plaintext, ciphertext, tag);
            ciphertext[0] ^= 0xFF;

            byte[] dest = new byte[plaintext.Length];
            AeadTestSupport.AssertAuthFailure(backend, () => gcm.Decrypt(nonce, ciphertext, tag, dest));
        });

    internal static void Assert_Decrypt_WrongAad_Throws(IPkcs11Backend backend) =>
        WithGcm(backend, gcm =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("bound to its aad");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            gcm.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes("aad-A"));

            byte[] dest = new byte[plaintext.Length];
            AeadTestSupport.AssertAuthFailure(backend, () =>
                gcm.Decrypt(nonce, ciphertext, tag, dest, Encoding.UTF8.GetBytes("aad-B")));
        });

    internal static void Assert_Decrypt_WrongNonce_Throws(IPkcs11Backend backend) =>
        WithGcm(backend, gcm =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("nonce bound");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            gcm.Encrypt(nonce, plaintext, ciphertext, tag);
            byte[] wrongNonce = Iota(12);
            wrongNonce[0] ^= 0xFF;

            byte[] dest = new byte[plaintext.Length];
            AeadTestSupport.AssertAuthFailure(backend, () => gcm.Decrypt(wrongNonce, ciphertext, tag, dest));
        });

    // === Known-answer test ================================================

    // McGrew & Viega AES-GCM test case 16 (256-bit key, 96-bit IV, with AAD): exercises encrypt/decrypt
    // and tag handling end-to-end against a published vector.
    internal static void Assert_Encrypt_KnownAnswer_MatchesReferenceVector(IPkcs11Backend backend)
    {
        byte[] key = H("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] nonce = H("cafebabefacedbaddecaf888");
        byte[] aad = H("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        byte[] pt = H("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        byte[] expectedCt = H("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
        byte[] expectedTag = H("76fc6ece0f4e1768cddf8853bb2d551b");

        WithImportedGcm(backend, key, gcm =>
        {
            byte[] ct = new byte[pt.Length];
            byte[] tag = new byte[expectedTag.Length];
            gcm.Encrypt(nonce, pt, ct, tag, aad);
            Assert.Equal(expectedCt, ct);
            Assert.Equal(expectedTag, tag);

            byte[] dec = new byte[pt.Length];
            gcm.Decrypt(nonce, expectedCt, expectedTag, dec, aad);
            Assert.Equal(pt, dec);
        });
    }
}
