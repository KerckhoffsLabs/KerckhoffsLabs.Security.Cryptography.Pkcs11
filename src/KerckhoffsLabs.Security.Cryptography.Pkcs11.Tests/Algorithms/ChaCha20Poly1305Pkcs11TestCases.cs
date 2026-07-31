using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic ChaCha20-Poly1305 tests: argument validation, AEAD round-trips, authenticity
/// negatives, and the RFC 8439 §2.8.2 known-answer vector. Every case but the non-ChaCha-key
/// constructor check needs a CKK_CHACHA20 key, so it skips where the backend does not advertise
/// <c>CKM_CHACHA20_POLY1305</c> (neither SoftHSM nor opencryptoki implement it today; the in-process
/// Managed suite covers the round-trips end-to-end via the BCL).
/// </summary>
internal static class ChaCha20Poly1305Pkcs11TestCases
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
            k.Destroy();
            k.Dispose();
        }
    }

    // Generates an ephemeral ChaCha20 key, wraps it as the adapter, runs the body, then destroys it.
    // Skips where the backend does not advertise CKM_CHACHA20_POLY1305 (the key type goes with it).
    // Uses CKM_GENERIC_SECRET_KEY_GEN because CKM_CHACHA20_KEY_GEN is not in PKCS#11 2.40.
    private static void WithChaCha(IPkcs11Backend backend, Action<ChaCha20Poly1305Pkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_CHACHA20_POLY1305))
            throw new SkipTestException("Backend does not advertise CKM_CHACHA20_POLY1305.");

        using var workspace = OpenWorkspace(backend);
        string label = $"chacha-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_CHACHA20)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_CHACHA20_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var chacha = new ChaCha20Poly1305Pkcs11(key);
            body(chacha);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    private static void WithImportedChaCha(IPkcs11Backend backend, byte[] rawKey, Action<ChaCha20Poly1305Pkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_CHACHA20_POLY1305))
            throw new SkipTestException("Backend does not advertise CKM_CHACHA20_POLY1305.");

        using var workspace = OpenWorkspace(backend);
        string label = $"chacha-kat-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_CHACHA20)
            .Label(label).Value(rawKey).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var chacha = new ChaCha20Poly1305Pkcs11(key);
            body(chacha);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Construction (only needs a non-ChaCha key) =======================

    internal static void Assert_Ctor_NonChaChaKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"chacha-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new ChaCha20Poly1305Pkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Argument validation (needs a constructed adapter, hence a ChaCha20 key) ===========

    internal static void Assert_Encrypt_InvalidNonceLength_Throws(IPkcs11Backend backend, int nonceLength) =>
        WithChaCha(backend, chacha =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                chacha.Encrypt(new byte[nonceLength], new byte[8], new byte[8], new byte[16]));
            Assert.Equal("nonce", ex.ParamName);
        });

    internal static void Assert_Decrypt_InvalidNonceLength_Throws(IPkcs11Backend backend, int nonceLength) =>
        WithChaCha(backend, chacha =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                chacha.Decrypt(new byte[nonceLength], new byte[8], new byte[16], new byte[8]));
            Assert.Equal("nonce", ex.ParamName);
        });

    internal static void Assert_Encrypt_InvalidTagLength_Throws(IPkcs11Backend backend, int tagLength) =>
        WithChaCha(backend, chacha =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                chacha.Encrypt(new byte[12], new byte[8], new byte[8], new byte[tagLength]));
            Assert.Equal("tagLength", ex.ParamName);
        });

    internal static void Assert_Decrypt_InvalidTagLength_Throws(IPkcs11Backend backend, int tagLength) =>
        WithChaCha(backend, chacha =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                chacha.Decrypt(new byte[12], new byte[8], new byte[tagLength], new byte[8]));
            Assert.Equal("tagLength", ex.ParamName);
        });

    internal static void Assert_Encrypt_CiphertextLengthMismatch_Throws(IPkcs11Backend backend) =>
        WithChaCha(backend, chacha =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                chacha.Encrypt(new byte[12], new byte[8], new byte[7], new byte[16]));
            Assert.Equal("ciphertext", ex.ParamName);
        });

    internal static void Assert_Decrypt_PlaintextLengthMismatch_Throws(IPkcs11Backend backend) =>
        WithChaCha(backend, chacha =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                chacha.Decrypt(new byte[12], new byte[8], new byte[16], new byte[7]));
            Assert.Equal("plaintext", ex.ParamName);
        });

    internal static void Assert_Encrypt_AfterDispose_Throws(IPkcs11Backend backend) =>
        WithChaCha(backend, chacha =>
        {
            chacha.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                chacha.Encrypt(new byte[12], new byte[8], new byte[8], new byte[16]));
        });

    internal static void Assert_Decrypt_AfterDispose_Throws(IPkcs11Backend backend) =>
        WithChaCha(backend, chacha =>
        {
            chacha.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                chacha.Decrypt(new byte[12], new byte[8], new byte[16], new byte[8]));
        });

    // === Real crypto (requires a ChaCha20-Poly1305-capable token) =========

    internal static void Assert_EncryptDecrypt_RoundTrips_WithAad(IPkcs11Backend backend) =>
        WithChaCha(backend, chacha =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("ChaCha20-Poly1305 round trip");
            byte[] aad = Encoding.UTF8.GetBytes("associated-data");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            chacha.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            byte[] decrypted = new byte[plaintext.Length];
            chacha.Decrypt(nonce, ciphertext, tag, decrypted, aad);

            Assert.Equal(plaintext, decrypted);
            Assert.NotEqual(plaintext, ciphertext);
        });

    internal static void Assert_EncryptDecrypt_RoundTrips_NoAad(IPkcs11Backend backend) =>
        WithChaCha(backend, chacha =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("no associated data");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            chacha.Encrypt(nonce, plaintext, ciphertext, tag);
            byte[] decrypted = new byte[plaintext.Length];
            chacha.Decrypt(nonce, ciphertext, tag, decrypted);

            Assert.Equal(plaintext, decrypted);
        });

    internal static void Assert_Decrypt_TamperedTag_Throws(IPkcs11Backend backend) =>
        WithChaCha(backend, chacha =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("authenticity");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            chacha.Encrypt(nonce, plaintext, ciphertext, tag);
            tag[0] ^= 0xFF;

            byte[] dest = new byte[plaintext.Length];
            AeadTestSupport.AssertAuthFailure(backend, () => chacha.Decrypt(nonce, ciphertext, tag, dest));
        });

    internal static void Assert_Decrypt_TamperedCiphertext_Throws(IPkcs11Backend backend) =>
        WithChaCha(backend, chacha =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("integrity matters");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            chacha.Encrypt(nonce, plaintext, ciphertext, tag);
            ciphertext[0] ^= 0xFF;

            byte[] dest = new byte[plaintext.Length];
            AeadTestSupport.AssertAuthFailure(backend, () => chacha.Decrypt(nonce, ciphertext, tag, dest));
        });

    internal static void Assert_Decrypt_WrongAad_Throws(IPkcs11Backend backend) =>
        WithChaCha(backend, chacha =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("bound to its aad");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            chacha.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes("aad-A"));

            byte[] dest = new byte[plaintext.Length];
            AeadTestSupport.AssertAuthFailure(backend, () =>
                chacha.Decrypt(nonce, ciphertext, tag, dest, Encoding.UTF8.GetBytes("aad-B")));
        });

    internal static void Assert_Decrypt_WrongNonce_Throws(IPkcs11Backend backend) =>
        WithChaCha(backend, chacha =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("nonce bound");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            chacha.Encrypt(nonce, plaintext, ciphertext, tag);
            byte[] wrongNonce = Iota(12);
            wrongNonce[0] ^= 0xFF;

            byte[] dest = new byte[plaintext.Length];
            AeadTestSupport.AssertAuthFailure(backend, () => chacha.Decrypt(wrongNonce, ciphertext, tag, dest));
        });

    // Known-answer test: RFC 8439 §2.8.2 (also confirmed via the BCL ChaCha20Poly1305 primitive).
    internal static void Assert_Encrypt_KnownAnswer_MatchesReferenceVector(IPkcs11Backend backend)
    {
        byte[] key = H("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = H("070000004041424344454647");
        byte[] aad = H("50515253c0c1c2c3c4c5c6c7");
        byte[] pt = Encoding.ASCII.GetBytes(
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        byte[] expectedCt = H("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
        byte[] expectedTag = H("1ae10b594f09e26a7e902ecbd0600691");

        WithImportedChaCha(backend, key, chacha =>
        {
            byte[] ct = new byte[pt.Length];
            byte[] tag = new byte[expectedTag.Length];
            chacha.Encrypt(nonce, pt, ct, tag, aad);
            Assert.Equal(expectedCt, ct);
            Assert.Equal(expectedTag, tag);

            byte[] dec = new byte[pt.Length];
            chacha.Decrypt(nonce, expectedCt, expectedTag, dec, aad);
            Assert.Equal(pt, dec);
        });
    }
}
