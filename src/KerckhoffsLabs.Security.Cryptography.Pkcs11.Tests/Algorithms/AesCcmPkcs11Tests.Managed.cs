using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// AesCcmPkcs11 over the in-process <c>ManagedSoftToken</c>. The managed token reports
/// <c>IsMessageApiSupported=false</c>, so these exercise the adapter's PKCS#11 v2.40 single-part
/// path (ciphertext‖tag) — the AES-CCM path that actually runs in CI, since SoftHSM implements no
/// AES-CCM and its rich behavioral tests skip. Real crypto is cross-checked against the BCL
/// <see cref="AesCcm"/> primitive (independent NIST SP 800-38C reference).
/// </summary>
public sealed class AesCcmPkcs11Tests_Managed
{
    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static byte[] Iota(int length)
    {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) b[i] = (byte)i;
        return b;
    }

    // Imports a known AES key by value and runs the body with an AesCcmPkcs11 over it (session key).
    private static void WithImportedCcm(byte[] key, Action<AesCcmPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("ccm").Value(key).Encrypt().Decrypt().Build();
        using var key1 = workspace.ImportKey(tpl);
        using var ccm = new AesCcmPkcs11(key1);
        body(ccm);
    }

    private static void WithAnyCcm(Action<AesCcmPkcs11> body) =>
        WithImportedCcm(RandomNumberGenerator.GetBytes(32), body);

    // AES-CCM authentication failures surface from the token as CKR_ENCRYPTED_DATA_INVALID.
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
        byte[] aad = "ccm-header"u8.ToArray();
        byte[] pt = RandomNumberGenerator.GetBytes(40);

        byte[] bclCt = new byte[pt.Length];
        byte[] bclTag = new byte[16];
        using (var bcl = new AesCcm(key))
            bcl.Encrypt(nonce, pt, bclCt, bclTag, aad);

        WithImportedCcm(key, ccm =>
        {
            byte[] ct = new byte[pt.Length];
            byte[] tag = new byte[16];
            ccm.Encrypt(nonce, pt, ct, tag, aad);
            Assert.Equal(bclCt, ct);
            Assert.Equal(bclTag, tag);

            byte[] dec = new byte[pt.Length];
            ccm.Decrypt(nonce, ct, tag, dec, aad);
            Assert.Equal(pt, dec);
        });
    }

    [Theory]
    [InlineData(7, 16)]  // shortest nonce, longest tag
    [InlineData(13, 4)]  // longest nonce, shortest tag
    [InlineData(12, 8)]
    [InlineData(11, 12)]
    public void EncryptDecrypt_MatchesBcl_AcrossNonceAndTagSizes(int nonceLen, int tagLen)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = Iota(nonceLen);
        byte[] aad = Iota(13);
        byte[] pt = Iota(24);

        byte[] bclCt = new byte[pt.Length];
        byte[] bclTag = new byte[tagLen];
        using (var bcl = new AesCcm(key))
            bcl.Encrypt(nonce, pt, bclCt, bclTag, aad);

        WithImportedCcm(key, ccm =>
        {
            byte[] ct = new byte[pt.Length];
            byte[] tag = new byte[tagLen];
            ccm.Encrypt(nonce, pt, ct, tag, aad);
            Assert.Equal(bclCt, ct);
            Assert.Equal(bclTag, tag);

            byte[] dec = new byte[pt.Length];
            ccm.Decrypt(nonce, ct, tag, dec, aad);
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
        using (var bcl = new AesCcm(key))
            bcl.Encrypt(nonce, pt, ct, tag, aad);

        WithImportedCcm(key, ccm =>
        {
            byte[] dec = new byte[pt.Length];
            ccm.Decrypt(nonce, ct, tag, dec, aad);
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
        using (var bcl = new AesCcm(key))
            bcl.Encrypt(nonce, empty, empty, bclTag, aad);

        WithImportedCcm(key, ccm =>
        {
            byte[] tag = new byte[16];
            ccm.Encrypt(nonce, [], [], tag, aad);
            Assert.Equal(bclTag, tag); // tag authenticates the AAD over an empty message
            ccm.Decrypt(nonce, [], tag, [], aad); // must not throw
        });
    }

    [Fact]
    public void EncryptDecrypt_NoAad_RoundTrips()
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = Iota(13);
        byte[] pt = "no associated data"u8.ToArray();

        WithImportedCcm(key, ccm =>
        {
            byte[] ct = new byte[pt.Length];
            byte[] tag = new byte[16];
            ccm.Encrypt(nonce, pt, ct, tag);
            byte[] dec = new byte[pt.Length];
            ccm.Decrypt(nonce, ct, tag, dec);
            Assert.Equal(pt, dec);
        });
    }

    // Known-answer test: expected bytes pinned from the BCL AesCcm primitive for a fixed
    // AES-256 key / 96-bit nonce / AAD (NIST SP 800-38C semantics).
    [Fact]
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

    // === Authenticity: every input the tag covers must be rejected when altered ===========

    [Fact]
    public void Decrypt_TamperedTag_Throws() => WithAnyCcm(ccm =>
    {
        byte[] nonce = Iota(12);
        byte[] pt = "authenticity"u8.ToArray();
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        ccm.Encrypt(nonce, pt, ct, tag);
        tag[0] ^= 0xFF;
        AssertAuthFailure(() => ccm.Decrypt(nonce, ct, tag, new byte[pt.Length]));
    });

    [Fact]
    public void Decrypt_TamperedCiphertext_Throws() => WithAnyCcm(ccm =>
    {
        byte[] nonce = Iota(12);
        byte[] pt = "integrity matters"u8.ToArray();
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        ccm.Encrypt(nonce, pt, ct, tag);
        ct[0] ^= 0xFF;
        AssertAuthFailure(() => ccm.Decrypt(nonce, ct, tag, new byte[pt.Length]));
    });

    [Fact]
    public void Decrypt_WrongAad_Throws() => WithAnyCcm(ccm =>
    {
        byte[] nonce = Iota(12);
        byte[] pt = "bound to its aad"u8.ToArray();
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        ccm.Encrypt(nonce, pt, ct, tag, "aad-A"u8.ToArray());
        AssertAuthFailure(() => ccm.Decrypt(nonce, ct, tag, new byte[pt.Length], "aad-B"u8.ToArray()));
    });

    [Fact]
    public void Decrypt_WrongNonce_Throws() => WithAnyCcm(ccm =>
    {
        byte[] nonce = Iota(12);
        byte[] pt = "nonce bound"u8.ToArray();
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        ccm.Encrypt(nonce, pt, ct, tag);
        byte[] wrongNonce = Iota(12);
        wrongNonce[0] ^= 0xFF;
        AssertAuthFailure(() => ccm.Decrypt(wrongNonce, ct, tag, new byte[pt.Length]));
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
        using (var bcl = new AesCcm(keyA))
            bcl.Encrypt(nonce, pt, ct, tag);

        WithImportedCcm(keyB, ccm =>
            AssertAuthFailure(() => ccm.Decrypt(nonce, ct, tag, new byte[pt.Length])));
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

        var ex = Assert.Throws<ArgumentException>(() => new AesCcmPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }

    [Theory]
    [InlineData(6)]   // below MinSize (7)
    [InlineData(14)]  // above MaxSize (13)
    public void Encrypt_InvalidNonceLength_Throws(int nonceLength) => WithAnyCcm(ccm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ccm.Encrypt(new byte[nonceLength], new byte[8], new byte[8], new byte[16]));
        Assert.Equal("nonce", ex.ParamName);
    });

    [Theory]
    [InlineData(2)]   // below MinSize (4)
    [InlineData(3)]   // violates SkipSize (2)
    [InlineData(18)]  // above MaxSize (16)
    public void Encrypt_InvalidTagLength_Throws(int tagLength) => WithAnyCcm(ccm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ccm.Encrypt(new byte[12], new byte[8], new byte[8], new byte[tagLength]));
        Assert.Equal("tagLength", ex.ParamName);
    });

    [Fact]
    public void Encrypt_CiphertextLengthMismatch_Throws() => WithAnyCcm(ccm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ccm.Encrypt(new byte[12], new byte[8], new byte[7], new byte[16]));
        Assert.Equal("ciphertext", ex.ParamName);
    });

    [Fact]
    public void Decrypt_PlaintextLengthMismatch_Throws() => WithAnyCcm(ccm =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ccm.Decrypt(new byte[12], new byte[8], new byte[16], new byte[7]));
        Assert.Equal("plaintext", ex.ParamName);
    });

    [Fact]
    public void Encrypt_AfterDispose_Throws() => WithAnyCcm(ccm =>
    {
        ccm.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            ccm.Encrypt(new byte[12], new byte[8], new byte[8], new byte[16]));
    });

    [Fact]
    public void Decrypt_AfterDispose_Throws() => WithAnyCcm(ccm =>
    {
        ccm.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            ccm.Decrypt(new byte[12], new byte[8], new byte[16], new byte[8]));
    });
}
