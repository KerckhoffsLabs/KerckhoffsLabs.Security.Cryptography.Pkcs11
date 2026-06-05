using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// AesGcmPkcs11 over the in-process <c>ManagedSoftToken</c>. The token reports
/// <c>IsMessageApiSupported=false</c>, so the adapter uses its PKCS#11 v2.40 single-part path
/// (ciphertext‖tag) — the path that always runs in CI. Real crypto is cross-checked against the BCL
/// <see cref="AesGcm"/> primitive. AES-GCM fixes the nonce at 12 bytes and allows 12–16 byte tags.
/// </summary>
public sealed class AesGcmPkcs11Tests_Managed
{
    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static byte[] Iota(int length)
    {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) b[i] = (byte)i;
        return b;
    }

    // Imports a known AES key by value and runs the body with an AesGcmPkcs11 over it (session key).
    private static void WithImportedGcm(byte[] key, Action<AesGcmPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("gcm").Value(key).Encrypt().Decrypt().Build();
        using var key1 = workspace.ImportKey(tpl);
        using var gcm = new AesGcmPkcs11(key1);
        body(gcm);
    }

    private static void WithAnyGcm(Action<AesGcmPkcs11> body) =>
        WithImportedGcm(RandomNumberGenerator.GetBytes(32), body);

    // AES-GCM authentication failures surface from the token as CKR_ENCRYPTED_DATA_INVALID.
    private static void AssertAuthFailure(Action decrypt)
    {
        var ex = Assert.ThrowsAny<Pkcs11Exception>(decrypt);
        Assert.Equal(CKR.CKR_ENCRYPTED_DATA_INVALID, ex.ReturnValue);
    }

    // === Real crypto: cross-checked against the BCL ======================================

    [Theory]
    [InlineData(16)] // AES-128
    [InlineData(24)] // AES-192
    [InlineData(32)] // AES-256
    public void Encrypt_MatchesBcl_AndRoundTrips_AcrossKeySizes(int keyLen)
    {
        byte[] key = RandomNumberGenerator.GetBytes(keyLen);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] aad = "authenticated-header"u8.ToArray();
        byte[] pt = RandomNumberGenerator.GetBytes(40);

        byte[] bclCt = new byte[pt.Length];
        byte[] bclTag = new byte[16];
        using (var bcl = new AesGcm(key, 16))
            bcl.Encrypt(nonce, pt, bclCt, bclTag, aad);

        WithImportedGcm(key, gcm =>
        {
            byte[] ct = new byte[pt.Length];
            byte[] tag = new byte[16];
            gcm.Encrypt(nonce, pt, ct, tag, aad);
            Assert.Equal(bclCt, ct);
            Assert.Equal(bclTag, tag);

            byte[] dec = new byte[pt.Length];
            gcm.Decrypt(nonce, ct, tag, dec, aad);
            Assert.Equal(pt, dec);
        });
    }

    [Theory]
    [InlineData(12)] // shortest tag
    [InlineData(13)]
    [InlineData(14)]
    [InlineData(15)]
    [InlineData(16)] // full tag
    public void EncryptDecrypt_MatchesBcl_AcrossTagSizes(int tagLen)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = Iota(12);
        byte[] aad = Iota(13);
        byte[] pt = Iota(24);

        byte[] bclCt = new byte[pt.Length];
        byte[] bclTag = new byte[tagLen];
        using (var bcl = new AesGcm(key, tagLen))
            bcl.Encrypt(nonce, pt, bclCt, bclTag, aad);

        WithImportedGcm(key, gcm =>
        {
            byte[] ct = new byte[pt.Length];
            byte[] tag = new byte[tagLen];
            gcm.Encrypt(nonce, pt, ct, tag, aad);
            Assert.Equal(bclCt, ct);
            Assert.Equal(bclTag, tag);

            byte[] dec = new byte[pt.Length];
            gcm.Decrypt(nonce, ct, tag, dec, aad);
            Assert.Equal(pt, dec);
        });
    }

    // Reverse direction: a ciphertext produced by the BCL must decrypt on the token.
    [Fact]
    public void Decrypt_BclCiphertext_RoundTrips()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = Iota(12);
        byte[] aad = "interop"u8.ToArray();
        byte[] pt = RandomNumberGenerator.GetBytes(20);

        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        using (var bcl = new AesGcm(key, 16))
            bcl.Encrypt(nonce, pt, ct, tag, aad);

        WithImportedGcm(key, gcm =>
        {
            byte[] dec = new byte[pt.Length];
            gcm.Decrypt(nonce, ct, tag, dec, aad);
            Assert.Equal(pt, dec);
        });
    }

    [Fact]
    public void EncryptDecrypt_EmptyPlaintext_AadOnly_MatchesBcl()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = Iota(12);
        byte[] aad = "aad-only authentication"u8.ToArray();

        byte[] empty = [];
        byte[] bclTag = new byte[16];
        using (var bcl = new AesGcm(key, 16))
            bcl.Encrypt(nonce, empty, empty, bclTag, aad);

        WithImportedGcm(key, gcm =>
        {
            byte[] tag = new byte[16];
            gcm.Encrypt(nonce, [], [], tag, aad);
            Assert.Equal(bclTag, tag); // tag authenticates the AAD over an empty message
            gcm.Decrypt(nonce, [], tag, [], aad); // must not throw
        });
    }

    [Fact]
    public void EncryptDecrypt_NoAad_RoundTrips()
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = Iota(12);
        byte[] pt = "no associated data"u8.ToArray();

        WithImportedGcm(key, gcm =>
        {
            byte[] ct = new byte[pt.Length];
            byte[] tag = new byte[16];
            gcm.Encrypt(nonce, pt, ct, tag);
            byte[] dec = new byte[pt.Length];
            gcm.Decrypt(nonce, ct, tag, dec);
            Assert.Equal(pt, dec);
        });
    }

    // Known-answer test: McGrew & Viega AES-GCM test case 16 (256-bit key, 96-bit IV, with AAD).
    [Fact]
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

    // === Authenticity: every input the tag covers must be rejected when altered ===========

    [Fact]
    public void Decrypt_TamperedTag_Throws() => WithAnyGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] pt = "authenticity"u8.ToArray();
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        gcm.Encrypt(nonce, pt, ct, tag);
        tag[0] ^= 0xFF;
        AssertAuthFailure(() => gcm.Decrypt(nonce, ct, tag, new byte[pt.Length]));
    });

    [Fact]
    public void Decrypt_TamperedCiphertext_Throws() => WithAnyGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] pt = "integrity matters"u8.ToArray();
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        gcm.Encrypt(nonce, pt, ct, tag);
        ct[0] ^= 0xFF;
        AssertAuthFailure(() => gcm.Decrypt(nonce, ct, tag, new byte[pt.Length]));
    });

    [Fact]
    public void Decrypt_WrongAad_Throws() => WithAnyGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] pt = "bound to its aad"u8.ToArray();
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        gcm.Encrypt(nonce, pt, ct, tag, "aad-A"u8.ToArray());
        AssertAuthFailure(() => gcm.Decrypt(nonce, ct, tag, new byte[pt.Length], "aad-B"u8.ToArray()));
    });

    [Fact]
    public void Decrypt_WrongNonce_Throws() => WithAnyGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] pt = "nonce bound"u8.ToArray();
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        gcm.Encrypt(nonce, pt, ct, tag);
        byte[] wrongNonce = Iota(12);
        wrongNonce[0] ^= 0xFF;
        AssertAuthFailure(() => gcm.Decrypt(wrongNonce, ct, tag, new byte[pt.Length]));
    });

    [Fact]
    public void Decrypt_WrongKey_Throws()
    {
        byte[] keyA = RandomNumberGenerator.GetBytes(32);
        byte[] keyB = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = Iota(12);
        byte[] pt = "wrong key cannot read this"u8.ToArray();

        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        using (var bcl = new AesGcm(keyA, 16))
            bcl.Encrypt(nonce, pt, ct, tag);

        WithImportedGcm(keyB, gcm =>
            AssertAuthFailure(() => gcm.Decrypt(nonce, ct, tag, new byte[pt.Length])));
    }

    // === Construction and argument validation (run before the native call) ================

    [Fact]
    public void Ctor_NonAesKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("gen").ValueLen(32).Sign().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new AesGcmPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }

    [Theory]
    [InlineData(8)]   // below the fixed 12-byte nonce
    [InlineData(13)]  // above it
    public void Encrypt_InvalidNonceLength_Throws(int nonceLength) => WithAnyGcm(gcm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            gcm.Encrypt(new byte[nonceLength], new byte[8], new byte[8], new byte[16]));
        Assert.Equal("nonce", ex.ParamName);
    });

    [Theory]
    [InlineData(8)]   // below MinSize (12)
    [InlineData(11)]  // still below MinSize
    [InlineData(17)]  // above MaxSize (16)
    public void Encrypt_InvalidTagLength_Throws(int tagLength) => WithAnyGcm(gcm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            gcm.Encrypt(new byte[12], new byte[8], new byte[8], new byte[tagLength]));
        Assert.Equal("tagLength", ex.ParamName);
    });

    [Fact]
    public void Encrypt_CiphertextLengthMismatch_Throws() => WithAnyGcm(gcm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            gcm.Encrypt(new byte[12], new byte[8], new byte[7], new byte[16]));
        Assert.Equal("ciphertext", ex.ParamName);
    });

    [Fact]
    public void Decrypt_PlaintextLengthMismatch_Throws() => WithAnyGcm(gcm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            gcm.Decrypt(new byte[12], new byte[8], new byte[16], new byte[7]));
        Assert.Equal("plaintext", ex.ParamName);
    });

    [Fact]
    public void Encrypt_AfterDispose_Throws() => WithAnyGcm(gcm =>
    {
        gcm.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            gcm.Encrypt(new byte[12], new byte[8], new byte[8], new byte[16]));
    });

    [Fact]
    public void Decrypt_AfterDispose_Throws() => WithAnyGcm(gcm =>
    {
        gcm.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            gcm.Decrypt(new byte[12], new byte[8], new byte[16], new byte[8]));
    });
}
