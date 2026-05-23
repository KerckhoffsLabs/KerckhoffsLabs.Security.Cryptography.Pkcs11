using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Adapters.Tests;

/// <summary>
/// Backend-free tests: argument validation and the static size descriptors, none of which
/// touch a token.
/// </summary>
public sealed class AesCcmPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new AesCcmPkcs11(key: null!));

    [Fact]
    public void NonceByteSizes_MirrorsBcl()
    {
        var actual = AesCcmPkcs11.NonceByteSizes;
        var expected = AesCcm.NonceByteSizes;
        Assert.Equal(expected.MinSize, actual.MinSize);
        Assert.Equal(expected.MaxSize, actual.MaxSize);
        Assert.Equal(expected.SkipSize, actual.SkipSize);
    }

    [Fact]
    public void TagByteSizes_MirrorsBcl()
    {
        var actual = AesCcmPkcs11.TagByteSizes;
        var expected = AesCcm.TagByteSizes;
        Assert.Equal(expected.MinSize, actual.MinSize);
        Assert.Equal(expected.MaxSize, actual.MaxSize);
        Assert.Equal(expected.SkipSize, actual.SkipSize);
    }
}

[Collection("SoftHsm")]
public sealed class AesCcmPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;
    public static bool SoftHsmSupportsAesCcm => SoftHsmBackendFixture.SoftHsmSupportsAesCcm;

    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static byte[] Iota(int length)
    {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) b[i] = (byte)i;
        return b;
    }

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    // Generates an ephemeral AES-256 key, wraps it as AesCcmPkcs11, runs the body, then destroys
    // the key. The body is the only thing a test needs to supply.
    private void WithCcm(Action<AesCcmPkcs11> body)
    {
        using var workspace = OpenWorkspace();
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

    // Imports a known AES key (by value) so a deterministic vector can be checked.
    private void WithImportedCcm(byte[] rawKey, Action<AesCcmPkcs11> body)
    {
        using var workspace = OpenWorkspace();
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

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonAesKey_Throws()
    {
        using var workspace = OpenWorkspace();
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

    // === Argument validation (runs before the native call, so no CCM support needed) ======

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData(6)]   // below MinSize (7)
    [InlineData(14)]  // above MaxSize (13)
    public void Encrypt_InvalidNonceLength_Throws(int nonceLength) => WithCcm(ccm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ccm.Encrypt(new byte[nonceLength], new byte[8], new byte[8], new byte[16]));
        Assert.Equal("nonce", ex.ParamName);
    });

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData(6)]
    [InlineData(14)]
    public void Decrypt_InvalidNonceLength_Throws(int nonceLength) => WithCcm(ccm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ccm.Decrypt(new byte[nonceLength], new byte[8], new byte[16], new byte[8]));
        Assert.Equal("nonce", ex.ParamName);
    });

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData(2)]   // below MinSize (4)
    [InlineData(3)]   // violates SkipSize (2)
    [InlineData(18)]  // above MaxSize (16)
    public void Encrypt_InvalidTagLength_Throws(int tagLength) => WithCcm(ccm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ccm.Encrypt(new byte[12], new byte[8], new byte[8], new byte[tagLength]));
        Assert.Equal("tagLength", ex.ParamName);
    });

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(18)]
    public void Decrypt_InvalidTagLength_Throws(int tagLength) => WithCcm(ccm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ccm.Decrypt(new byte[12], new byte[8], new byte[tagLength], new byte[8]));
        Assert.Equal("tagLength", ex.ParamName);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Encrypt_CiphertextLengthMismatch_Throws() => WithCcm(ccm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ccm.Encrypt(new byte[12], new byte[8], new byte[7], new byte[16]));
        Assert.Equal("ciphertext", ex.ParamName);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decrypt_PlaintextLengthMismatch_Throws() => WithCcm(ccm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ccm.Decrypt(new byte[12], new byte[8], new byte[16], new byte[7]));
        Assert.Equal("plaintext", ex.ParamName);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Encrypt_AfterDispose_Throws() => WithCcm(ccm =>
    {
        ccm.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            ccm.Encrypt(new byte[12], new byte[8], new byte[8], new byte[16]));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decrypt_AfterDispose_Throws() => WithCcm(ccm =>
    {
        ccm.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            ccm.Decrypt(new byte[12], new byte[8], new byte[16], new byte[8]));
    });

    // === Real crypto (SoftHSM does not implement AES-CCM, so these are gated and skip there;
    //     they exercise the param marshalling + round-trip on any CCM-capable backend) =========

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsAesCcm))]
    public void EncryptDecrypt_RoundTrips_WithAad() => WithCcm(ccm =>
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
        Assert.NotEqual(plaintext, ciphertext); // sanity: data was actually transformed
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsAesCcm))]
    public void EncryptDecrypt_RoundTrips_NoAad() => WithCcm(ccm =>
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

    [ConditionalTheory(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsAesCcm))]
    [InlineData(7, 16)]
    [InlineData(12, 8)]
    [InlineData(13, 4)]
    public void EncryptDecrypt_RoundTrips_VariousNonceAndTagSizes(int nonceLen, int tagLen) => WithCcm(ccm =>
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

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsAesCcm))]
    public void EncryptDecrypt_EmptyPlaintext_RoundTrips() => WithCcm(ccm =>
    {
        byte[] nonce = Iota(12);
        byte[] aad = Encoding.UTF8.GetBytes("aad-only authentication");
        byte[] tag = new byte[16];

        ccm.Encrypt(nonce, [], [], tag, aad);
        ccm.Decrypt(nonce, [], tag, [], aad); // must not throw — tag authenticates the AAD
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsAesCcm))]
    public void Decrypt_TamperedTag_Throws() => WithCcm(ccm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = Encoding.UTF8.GetBytes("authenticity");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        ccm.Encrypt(nonce, plaintext, ciphertext, tag);
        tag[0] ^= 0xFF;

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Exception>(() => ccm.Decrypt(nonce, ciphertext, tag, dest));
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsAesCcm))]
    public void Decrypt_TamperedCiphertext_Throws() => WithCcm(ccm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = Encoding.UTF8.GetBytes("integrity matters");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        ccm.Encrypt(nonce, plaintext, ciphertext, tag);
        ciphertext[0] ^= 0xFF;

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Exception>(() => ccm.Decrypt(nonce, ciphertext, tag, dest));
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsAesCcm))]
    public void Decrypt_WrongAad_Throws() => WithCcm(ccm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = Encoding.UTF8.GetBytes("bound to its aad");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        ccm.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes("aad-A"));

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Exception>(() =>
            ccm.Decrypt(nonce, ciphertext, tag, dest, Encoding.UTF8.GetBytes("aad-B")));
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsAesCcm))]
    public void Decrypt_WrongNonce_Throws() => WithCcm(ccm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = Encoding.UTF8.GetBytes("nonce bound");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        ccm.Encrypt(nonce, plaintext, ciphertext, tag);
        byte[] wrongNonce = Iota(12);
        wrongNonce[0] ^= 0xFF;

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Exception>(() => ccm.Decrypt(wrongNonce, ciphertext, tag, dest));
    });

    // Known-answer test: expected bytes are pinned from the BCL AesCcm primitive (independent
    // reference, NIST SP 800-38C semantics) for a fixed AES-256 key / 96-bit nonce / AAD.
    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsAesCcm))]
    public void Encrypt_KnownAnswer_MatchesReferenceVector()
    {
        byte[] key = H("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        byte[] nonce = H("101112131415161718191a1b");
        byte[] aad = H("000102030405060708090a0b0c0d0e0f10111213");
        byte[] pt = H("202122232425262728292a2b2c2d2e2f3031323334353637");
        byte[] expectedCt = H("04f883aeb3bd0730eaf50bb6de4fa2212034e4e41b0e75e5");
        byte[] expectedTag = H("9bba3f3a107f3239bd63902923f80371");

        WithImportedCcm(key, ccm =>
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
