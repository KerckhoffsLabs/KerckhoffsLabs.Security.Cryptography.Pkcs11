using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// ChaCha20Poly1305Pkcs11 over the in-process <c>ManagedSoftToken</c>. The token reports
/// <c>IsMessageApiSupported=false</c>, so the adapter uses its PKCS#11 v2.40 single-part path
/// (ciphertext‖tag). Real crypto is cross-checked against the BCL <see cref="ChaCha20Poly1305"/>
/// primitive (RFC 8439). ChaCha20-Poly1305 fixes the key at 32 bytes, the nonce at 12, and the tag
/// at 16. The crypto cases are gated on platform support.
/// </summary>
public sealed class ChaCha20Poly1305Pkcs11Tests_Managed
{
    public static bool Supported => ChaCha20Poly1305.IsSupported;

    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static byte[] Iota(int length)
    {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) b[i] = (byte)i;
        return b;
    }

    // Imports a known 32-byte ChaCha20 key by value and runs the body with a wrapper over it.
    private static void WithImportedChaCha(byte[] key, Action<ChaCha20Poly1305Pkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_CHACHA20)
            .Label("chacha").Value(key).Encrypt().Decrypt().Build();
        using var k = workspace.ImportKey(tpl);
        using var chacha = new ChaCha20Poly1305Pkcs11(k);
        body(chacha);
    }

    private static void WithAnyChaCha(Action<ChaCha20Poly1305Pkcs11> body) =>
        WithImportedChaCha(RandomNumberGenerator.GetBytes(32), body);

    // ChaCha20-Poly1305 authentication failures surface from the token as CKR_ENCRYPTED_DATA_INVALID.
    private static void AssertAuthFailure(Action decrypt)
    {
        var ex = Assert.ThrowsAny<Pkcs11Exception>(decrypt);
        Assert.Equal(CKR.CKR_ENCRYPTED_DATA_INVALID, ex.ReturnValue);
    }

    // === Real crypto: cross-checked against the BCL ======================================

    [ConditionalFact(nameof(Supported))]
    public void Encrypt_MatchesBcl_AndRoundTrips()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] aad = "aead-header"u8.ToArray();
        byte[] pt = RandomNumberGenerator.GetBytes(48);

        byte[] bclCt = new byte[pt.Length];
        byte[] bclTag = new byte[16];
        using (var bcl = new ChaCha20Poly1305(key))
            bcl.Encrypt(nonce, pt, bclCt, bclTag, aad);

        WithImportedChaCha(key, chacha =>
        {
            byte[] ct = new byte[pt.Length];
            byte[] tag = new byte[16];
            chacha.Encrypt(nonce, pt, ct, tag, aad);
            Assert.Equal(bclCt, ct);
            Assert.Equal(bclTag, tag);

            byte[] dec = new byte[pt.Length];
            chacha.Decrypt(nonce, ct, tag, dec, aad);
            Assert.Equal(pt, dec);
        });
    }

    // Reverse direction: a ciphertext produced by the BCL must decrypt on the token.
    [ConditionalFact(nameof(Supported))]
    public void Decrypt_BclCiphertext_RoundTrips()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = Iota(12);
        byte[] aad = "interop"u8.ToArray();
        byte[] pt = RandomNumberGenerator.GetBytes(24);

        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        using (var bcl = new ChaCha20Poly1305(key))
            bcl.Encrypt(nonce, pt, ct, tag, aad);

        WithImportedChaCha(key, chacha =>
        {
            byte[] dec = new byte[pt.Length];
            chacha.Decrypt(nonce, ct, tag, dec, aad);
            Assert.Equal(pt, dec);
        });
    }

    [ConditionalFact(nameof(Supported))]
    public void EncryptDecrypt_EmptyPlaintext_AadOnly_MatchesBcl()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = Iota(12);
        byte[] aad = "aad-only authentication"u8.ToArray();

        byte[] empty = [];
        byte[] bclTag = new byte[16];
        using (var bcl = new ChaCha20Poly1305(key))
            bcl.Encrypt(nonce, empty, empty, bclTag, aad);

        WithImportedChaCha(key, chacha =>
        {
            byte[] tag = new byte[16];
            chacha.Encrypt(nonce, [], [], tag, aad);
            Assert.Equal(bclTag, tag); // tag authenticates the AAD over an empty message
            chacha.Decrypt(nonce, [], tag, [], aad); // must not throw
        });
    }

    [ConditionalFact(nameof(Supported))]
    public void EncryptDecrypt_NoAad_RoundTrips()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = Iota(12);
        byte[] pt = "no associated data"u8.ToArray();

        WithImportedChaCha(key, chacha =>
        {
            byte[] ct = new byte[pt.Length];
            byte[] tag = new byte[16];
            chacha.Encrypt(nonce, pt, ct, tag);
            byte[] dec = new byte[pt.Length];
            chacha.Decrypt(nonce, ct, tag, dec);
            Assert.Equal(pt, dec);
        });
    }

    // Known-answer test: RFC 8439 §2.8.2 AEAD_CHACHA20_POLY1305 example.
    [ConditionalFact(nameof(Supported))]
    public void Encrypt_KnownAnswer_MatchesReferenceVector()
    {
        byte[] key = H("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = H("070000004041424344454647");
        byte[] aad = H("50515253c0c1c2c3c4c5c6c7");
        byte[] pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."u8.ToArray();
        byte[] expectedCt = H("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
        byte[] expectedTag = H("1ae10b594f09e26a7e902ecbd0600691");

        WithImportedChaCha(key, chacha =>
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

    // === Authenticity: every input the tag covers must be rejected when altered ===========

    [ConditionalFact(nameof(Supported))]
    public void Decrypt_TamperedTag_Throws() => WithAnyChaCha(chacha =>
    {
        byte[] nonce = Iota(12);
        byte[] pt = "authenticity"u8.ToArray();
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        chacha.Encrypt(nonce, pt, ct, tag);
        tag[0] ^= 0xFF;
        AssertAuthFailure(() => chacha.Decrypt(nonce, ct, tag, new byte[pt.Length]));
    });

    [ConditionalFact(nameof(Supported))]
    public void Decrypt_TamperedCiphertext_Throws() => WithAnyChaCha(chacha =>
    {
        byte[] nonce = Iota(12);
        byte[] pt = "integrity matters"u8.ToArray();
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        chacha.Encrypt(nonce, pt, ct, tag);
        ct[0] ^= 0xFF;
        AssertAuthFailure(() => chacha.Decrypt(nonce, ct, tag, new byte[pt.Length]));
    });

    [ConditionalFact(nameof(Supported))]
    public void Decrypt_WrongAad_Throws() => WithAnyChaCha(chacha =>
    {
        byte[] nonce = Iota(12);
        byte[] pt = "bound to its aad"u8.ToArray();
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        chacha.Encrypt(nonce, pt, ct, tag, "aad-A"u8.ToArray());
        AssertAuthFailure(() => chacha.Decrypt(nonce, ct, tag, new byte[pt.Length], "aad-B"u8.ToArray()));
    });

    [ConditionalFact(nameof(Supported))]
    public void Decrypt_WrongNonce_Throws() => WithAnyChaCha(chacha =>
    {
        byte[] nonce = Iota(12);
        byte[] pt = "nonce bound"u8.ToArray();
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        chacha.Encrypt(nonce, pt, ct, tag);
        byte[] wrongNonce = Iota(12);
        wrongNonce[0] ^= 0xFF;
        AssertAuthFailure(() => chacha.Decrypt(wrongNonce, ct, tag, new byte[pt.Length]));
    });

    [ConditionalFact(nameof(Supported))]
    public void Decrypt_WrongKey_Throws()
    {
        byte[] keyA = RandomNumberGenerator.GetBytes(32);
        byte[] keyB = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = Iota(12);
        byte[] pt = "wrong key cannot read this"u8.ToArray();

        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        using (var bcl = new ChaCha20Poly1305(keyA))
            bcl.Encrypt(nonce, pt, ct, tag);

        WithImportedChaCha(keyB, chacha =>
            AssertAuthFailure(() => chacha.Decrypt(nonce, ct, tag, new byte[pt.Length])));
    }

    // === Construction and argument validation (run before the native call) ================

    [Fact]
    public void Ctor_NonChaChaKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("gen").ValueLen(32).Sign().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new ChaCha20Poly1305Pkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }

    [ConditionalTheory(nameof(Supported))]
    [InlineData(11)] // below the fixed 12-byte nonce
    [InlineData(13)] // above it
    public void Encrypt_InvalidNonceLength_Throws(int nonceLength) => WithAnyChaCha(chacha =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            chacha.Encrypt(new byte[nonceLength], new byte[8], new byte[8], new byte[16]));
        Assert.Equal("nonce", ex.ParamName);
    });

    [ConditionalTheory(nameof(Supported))]
    [InlineData(15)] // below the fixed 16-byte tag
    [InlineData(17)] // above it
    public void Encrypt_InvalidTagLength_Throws(int tagLength) => WithAnyChaCha(chacha =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            chacha.Encrypt(new byte[12], new byte[8], new byte[8], new byte[tagLength]));
        Assert.Equal("tagLength", ex.ParamName);
    });

    [ConditionalFact(nameof(Supported))]
    public void Encrypt_CiphertextLengthMismatch_Throws() => WithAnyChaCha(chacha =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            chacha.Encrypt(new byte[12], new byte[8], new byte[7], new byte[16]));
        Assert.Equal("ciphertext", ex.ParamName);
    });

    [ConditionalFact(nameof(Supported))]
    public void Decrypt_PlaintextLengthMismatch_Throws() => WithAnyChaCha(chacha =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            chacha.Decrypt(new byte[12], new byte[8], new byte[16], new byte[7]));
        Assert.Equal("plaintext", ex.ParamName);
    });

    [ConditionalFact(nameof(Supported))]
    public void Encrypt_AfterDispose_Throws() => WithAnyChaCha(chacha =>
    {
        chacha.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            chacha.Encrypt(new byte[12], new byte[8], new byte[8], new byte[16]));
    });

    [ConditionalFact(nameof(Supported))]
    public void Decrypt_AfterDispose_Throws() => WithAnyChaCha(chacha =>
    {
        chacha.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            chacha.Decrypt(new byte[12], new byte[8], new byte[16], new byte[8]));
    });
}
