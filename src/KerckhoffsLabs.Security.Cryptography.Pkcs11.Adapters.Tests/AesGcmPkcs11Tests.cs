using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Adapters.Tests;

/// <summary>
/// Backend-free tests: argument validation and the static size descriptors, none of which
/// touch a token.
/// </summary>
public sealed class AesGcmPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new AesGcmPkcs11(key: null!));

    [Fact]
    public void NonceByteSizes_MirrorsBcl()
    {
        var actual = AesGcmPkcs11.NonceByteSizes;
        var expected = AesGcm.NonceByteSizes;
        Assert.Equal(expected.MinSize, actual.MinSize);
        Assert.Equal(expected.MaxSize, actual.MaxSize);
        Assert.Equal(expected.SkipSize, actual.SkipSize);
    }

    [Fact]
    public void TagByteSizes_MirrorsBcl()
    {
        var actual = AesGcmPkcs11.TagByteSizes;
        var expected = AesGcm.TagByteSizes;
        Assert.Equal(expected.MinSize, actual.MinSize);
        Assert.Equal(expected.MaxSize, actual.MaxSize);
        Assert.Equal(expected.SkipSize, actual.SkipSize);
    }
}

[Collection("SoftHsm")]
public sealed class AesGcmPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

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

    // Generates an ephemeral AES-256 key, wraps it as AesGcmPkcs11, runs the body, then destroys
    // the key. The body is the only thing a test needs to supply.
    private void WithGcm(Action<AesGcmPkcs11> body)
    {
        using var workspace = OpenWorkspace();
        string label = $"gcm-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            using (var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t)) { }
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
    private void WithImportedGcm(byte[] rawKey, Action<AesGcmPkcs11> body)
    {
        using var workspace = OpenWorkspace();
        string label = $"gcm-kat-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(rawKey).Encrypt().Decrypt().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var gcm = new AesGcmPkcs11(key);
            body(gcm);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Construction =====================================================

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonAesKey_Throws()
    {
        using var workspace = OpenWorkspace();
        string label = $"gcm-nonaes-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(32).Sign().OnToken().Build())
        {
            using (var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t)) { }
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

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData(8)]   // below the fixed 12-byte nonce
    [InlineData(13)]  // above it
    public void Encrypt_InvalidNonceLength_Throws(int nonceLength) => WithGcm(gcm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            gcm.Encrypt(new byte[nonceLength], new byte[8], new byte[8], new byte[16]));
        Assert.Equal("nonce", ex.ParamName);
    });

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData(8)]
    [InlineData(13)]
    public void Decrypt_InvalidNonceLength_Throws(int nonceLength) => WithGcm(gcm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            gcm.Decrypt(new byte[nonceLength], new byte[8], new byte[16], new byte[8]));
        Assert.Equal("nonce", ex.ParamName);
    });

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData(8)]   // below MinSize (12)
    [InlineData(11)]  // still below MinSize
    [InlineData(17)]  // above MaxSize (16)
    public void Encrypt_InvalidTagLength_Throws(int tagLength) => WithGcm(gcm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            gcm.Encrypt(new byte[12], new byte[8], new byte[8], new byte[tagLength]));
        Assert.Equal("tagLength", ex.ParamName);
    });

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData(8)]
    [InlineData(11)]
    [InlineData(17)]
    public void Decrypt_InvalidTagLength_Throws(int tagLength) => WithGcm(gcm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            gcm.Decrypt(new byte[12], new byte[8], new byte[tagLength], new byte[8]));
        Assert.Equal("tagLength", ex.ParamName);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Encrypt_CiphertextLengthMismatch_Throws() => WithGcm(gcm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            gcm.Encrypt(new byte[12], new byte[8], new byte[7], new byte[16]));
        Assert.Equal("ciphertext", ex.ParamName);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decrypt_PlaintextLengthMismatch_Throws() => WithGcm(gcm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            gcm.Decrypt(new byte[12], new byte[8], new byte[16], new byte[7]));
        Assert.Equal("plaintext", ex.ParamName);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Encrypt_AfterDispose_Throws() => WithGcm(gcm =>
    {
        gcm.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            gcm.Encrypt(new byte[12], new byte[8], new byte[8], new byte[16]));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decrypt_AfterDispose_Throws() => WithGcm(gcm =>
    {
        gcm.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            gcm.Decrypt(new byte[12], new byte[8], new byte[16], new byte[8]));
    });

    // === Round-trips (SoftHSM implements AES-GCM, so these execute) =========

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptDecrypt_RoundTrips_WithAad() => WithGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("AES-GCM round trip");
        byte[] aad = System.Text.Encoding.UTF8.GetBytes("associated-data");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        byte[] decrypted = new byte[plaintext.Length];
        gcm.Decrypt(nonce, ciphertext, tag, decrypted, aad);

        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext); // sanity: data was actually transformed
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptDecrypt_RoundTrips_NoAad() => WithGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("no associated data");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag);
        byte[] decrypted = new byte[plaintext.Length];
        gcm.Decrypt(nonce, ciphertext, tag, decrypted);

        Assert.Equal(plaintext, decrypted);
    });

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData(12)]
    [InlineData(16)]
    public void EncryptDecrypt_RoundTrips_VariousTagSizes(int tagLen) => WithGcm(gcm =>
    {
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

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decrypt_TamperedTag_Throws() => WithGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("authenticity");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag);
        tag[0] ^= 0xFF;

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Exception>(() => gcm.Decrypt(nonce, ciphertext, tag, dest));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decrypt_TamperedCiphertext_Throws() => WithGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("integrity matters");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag);
        ciphertext[0] ^= 0xFF;

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Exception>(() => gcm.Decrypt(nonce, ciphertext, tag, dest));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decrypt_WrongAad_Throws() => WithGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("bound to its aad");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag, System.Text.Encoding.UTF8.GetBytes("aad-A"));

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Exception>(() =>
            gcm.Decrypt(nonce, ciphertext, tag, dest, System.Text.Encoding.UTF8.GetBytes("aad-B")));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decrypt_WrongNonce_Throws() => WithGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("nonce bound");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag);
        byte[] wrongNonce = Iota(12);
        wrongNonce[0] ^= 0xFF;

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Exception>(() => gcm.Decrypt(wrongNonce, ciphertext, tag, dest));
    });

    // Known-answer test: McGrew & Viega AES-GCM test case 16 (256-bit key, 96-bit IV, with AAD).
    // Exercises the adapter's encrypt/decrypt + tag handling end-to-end against a published vector.
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Encrypt_KnownAnswer_MatchesReferenceVector()
    {
        byte[] key = H("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] nonce = H("cafebabefacedbaddecaf888");
        byte[] aad = H("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        byte[] pt = H("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        byte[] expectedCt = H("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
        byte[] expectedTag = H("76fc6ece0f4e1768cddf8853bb2d551b");

        WithImportedGcm(key, gcm =>
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
