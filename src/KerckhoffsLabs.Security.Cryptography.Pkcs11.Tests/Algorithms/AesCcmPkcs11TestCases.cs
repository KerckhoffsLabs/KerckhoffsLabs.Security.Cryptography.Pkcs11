using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic AesCcmPkcs11 tests: argument validation (runs before any native call), AEAD
/// round-trips, authenticity negatives, and a BCL-pinned known-answer vector. The real-crypto cases
/// skip where the backend does not advertise <c>CKM_AES_CCM</c> (neither SoftHSM nor opencryptoki
/// implement AES-CCM today, so they exercise the parameter marshalling against any future CCM backend;
/// the in-process Managed suite covers the round-trips end-to-end via the BCL).
/// </summary>
internal static class AesCcmPkcs11TestCases
{
    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static byte[] Iota(int length)
    {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) b[i] = (byte)i;
        return b;
    }

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.Library.OpenWorkspace(backend.TokenLabel, CKU.CKU_USER, new SecurePin(backend.UserPin.Span));

    private static void RequireCcm(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_AES_CCM))
            throw new SkipTestException("Backend does not advertise CKM_AES_CCM.");
    }

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    // Generates an ephemeral AES-256 key, wraps it as AesCcmPkcs11, runs the body, then destroys it.
    // Does not require CCM — argument-validation cases use this and throw before any native call.
    private static void WithCcm(IPkcs11Backend backend, Action<AesCcmPkcs11> body)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"ccm-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var ccm = new AesCcmPkcs11(key);
            body(ccm);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    private static void WithImportedCcm(IPkcs11Backend backend, byte[] rawKey, Action<AesCcmPkcs11> body)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"ccm-kat-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(rawKey).Encrypt().Decrypt().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var ccm = new AesCcmPkcs11(key);
            body(ccm);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Construction =====================================================

    internal static void Assert_Ctor_NonAesKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"ccm-nonaes-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(32).Sign().OnToken().Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new AesCcmPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Argument validation (no CCM support needed) ======================

    internal static void Assert_Encrypt_InvalidNonceLength_Throws(IPkcs11Backend backend, int nonceLength) =>
        WithCcm(backend, ccm =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                ccm.Encrypt(new byte[nonceLength], new byte[8], new byte[8], new byte[16]));
            Assert.Equal("nonce", ex.ParamName);
        });

    internal static void Assert_Decrypt_InvalidNonceLength_Throws(IPkcs11Backend backend, int nonceLength) =>
        WithCcm(backend, ccm =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                ccm.Decrypt(new byte[nonceLength], new byte[8], new byte[16], new byte[8]));
            Assert.Equal("nonce", ex.ParamName);
        });

    internal static void Assert_Encrypt_InvalidTagLength_Throws(IPkcs11Backend backend, int tagLength) =>
        WithCcm(backend, ccm =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                ccm.Encrypt(new byte[12], new byte[8], new byte[8], new byte[tagLength]));
            Assert.Equal("tagLength", ex.ParamName);
        });

    internal static void Assert_Decrypt_InvalidTagLength_Throws(IPkcs11Backend backend, int tagLength) =>
        WithCcm(backend, ccm =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                ccm.Decrypt(new byte[12], new byte[8], new byte[tagLength], new byte[8]));
            Assert.Equal("tagLength", ex.ParamName);
        });

    internal static void Assert_Encrypt_CiphertextLengthMismatch_Throws(IPkcs11Backend backend) =>
        WithCcm(backend, ccm =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                ccm.Encrypt(new byte[12], new byte[8], new byte[7], new byte[16]));
            Assert.Equal("ciphertext", ex.ParamName);
        });

    internal static void Assert_Decrypt_PlaintextLengthMismatch_Throws(IPkcs11Backend backend) =>
        WithCcm(backend, ccm =>
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                ccm.Decrypt(new byte[12], new byte[8], new byte[16], new byte[7]));
            Assert.Equal("plaintext", ex.ParamName);
        });

    internal static void Assert_Encrypt_AfterDispose_Throws(IPkcs11Backend backend) =>
        WithCcm(backend, ccm =>
        {
            ccm.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                ccm.Encrypt(new byte[12], new byte[8], new byte[8], new byte[16]));
        });

    internal static void Assert_Decrypt_AfterDispose_Throws(IPkcs11Backend backend) =>
        WithCcm(backend, ccm =>
        {
            ccm.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                ccm.Decrypt(new byte[12], new byte[8], new byte[16], new byte[8]));
        });

    // === Real crypto (requires a CCM-capable token) =======================

    internal static void Assert_EncryptDecrypt_RoundTrips_WithAad(IPkcs11Backend backend)
    {
        RequireCcm(backend);
        WithCcm(backend, ccm =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("AES-CCM round trip");
            byte[] aad = Encoding.UTF8.GetBytes("associated-data");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            ccm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            byte[] decrypted = new byte[plaintext.Length];
            ccm.Decrypt(nonce, ciphertext, tag, decrypted, aad);

            Assert.Equal(plaintext, decrypted);
            Assert.NotEqual(plaintext, ciphertext);
        });
    }

    internal static void Assert_EncryptDecrypt_RoundTrips_NoAad(IPkcs11Backend backend)
    {
        RequireCcm(backend);
        WithCcm(backend, ccm =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("no associated data");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            ccm.Encrypt(nonce, plaintext, ciphertext, tag);
            byte[] decrypted = new byte[plaintext.Length];
            ccm.Decrypt(nonce, ciphertext, tag, decrypted);

            Assert.Equal(plaintext, decrypted);
        });
    }

    internal static void Assert_EncryptDecrypt_RoundTrips_VariousNonceAndTagSizes(IPkcs11Backend backend, int nonceLen, int tagLen)
    {
        RequireCcm(backend);
        WithCcm(backend, ccm =>
        {
            byte[] nonce = Iota(nonceLen);
            byte[] plaintext = Iota(40);
            byte[] aad = Iota(13);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[tagLen];

            ccm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            byte[] decrypted = new byte[plaintext.Length];
            ccm.Decrypt(nonce, ciphertext, tag, decrypted, aad);

            Assert.Equal(plaintext, decrypted);
        });
    }

    internal static void Assert_EncryptDecrypt_EmptyPlaintext_RoundTrips(IPkcs11Backend backend)
    {
        RequireCcm(backend);
        WithCcm(backend, ccm =>
        {
            byte[] nonce = Iota(12);
            byte[] aad = Encoding.UTF8.GetBytes("aad-only authentication");
            byte[] tag = new byte[16];

            ccm.Encrypt(nonce, [], [], tag, aad);
            // The tag authenticates the AAD even with empty plaintext; the matching-AAD decrypt must succeed.
            Assert.Null(Record.Exception(() => ccm.Decrypt(nonce, [], tag, [], aad)));
        });
    }

    internal static void Assert_Decrypt_TamperedTag_Throws(IPkcs11Backend backend)
    {
        RequireCcm(backend);
        WithCcm(backend, ccm =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("authenticity");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            ccm.Encrypt(nonce, plaintext, ciphertext, tag);
            tag[0] ^= 0xFF;

            byte[] dest = new byte[plaintext.Length];
            AeadTestSupport.AssertAuthFailure(backend, () => ccm.Decrypt(nonce, ciphertext, tag, dest));
        });
    }

    internal static void Assert_Decrypt_TamperedCiphertext_Throws(IPkcs11Backend backend)
    {
        RequireCcm(backend);
        WithCcm(backend, ccm =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("integrity matters");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            ccm.Encrypt(nonce, plaintext, ciphertext, tag);
            ciphertext[0] ^= 0xFF;

            byte[] dest = new byte[plaintext.Length];
            AeadTestSupport.AssertAuthFailure(backend, () => ccm.Decrypt(nonce, ciphertext, tag, dest));
        });
    }

    internal static void Assert_Decrypt_WrongAad_Throws(IPkcs11Backend backend)
    {
        RequireCcm(backend);
        WithCcm(backend, ccm =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("bound to its aad");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            ccm.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes("aad-A"));

            byte[] dest = new byte[plaintext.Length];
            AeadTestSupport.AssertAuthFailure(backend, () =>
                ccm.Decrypt(nonce, ciphertext, tag, dest, Encoding.UTF8.GetBytes("aad-B")));
        });
    }

    internal static void Assert_Decrypt_WrongNonce_Throws(IPkcs11Backend backend)
    {
        RequireCcm(backend);
        WithCcm(backend, ccm =>
        {
            byte[] nonce = Iota(12);
            byte[] plaintext = Encoding.UTF8.GetBytes("nonce bound");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            ccm.Encrypt(nonce, plaintext, ciphertext, tag);
            byte[] wrongNonce = Iota(12);
            wrongNonce[0] ^= 0xFF;

            byte[] dest = new byte[plaintext.Length];
            AeadTestSupport.AssertAuthFailure(backend, () => ccm.Decrypt(wrongNonce, ciphertext, tag, dest));
        });
    }

    // Known-answer test: expected bytes pinned from the BCL AesCcm primitive (NIST SP 800-38C semantics)
    // for a fixed AES-256 key / 96-bit nonce / AAD.
    internal static void Assert_Encrypt_KnownAnswer_MatchesReferenceVector(IPkcs11Backend backend)
    {
        RequireCcm(backend);
        byte[] key = H("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        byte[] nonce = H("101112131415161718191a1b");
        byte[] aad = H("000102030405060708090a0b0c0d0e0f10111213");
        byte[] pt = H("202122232425262728292a2b2c2d2e2f3031323334353637");
        byte[] expectedCt = H("04f883aeb3bd0730eaf50bb6de4fa2212034e4e41b0e75e5");
        byte[] expectedTag = H("9bba3f3a107f3239bd63902923f80371");

        WithImportedCcm(backend, key, ccm =>
        {
            byte[] ct = new byte[pt.Length];
            byte[] tag = new byte[expectedTag.Length];
            ccm.Encrypt(nonce, pt, ct, tag, aad);
            Assert.Equal(expectedCt, ct);
            Assert.Equal(expectedTag, tag);

            byte[] dec = new byte[pt.Length];
            ccm.Decrypt(nonce, expectedCt, expectedTag, dec, aad);
            Assert.Equal(pt, dec);
        });
    }
}
