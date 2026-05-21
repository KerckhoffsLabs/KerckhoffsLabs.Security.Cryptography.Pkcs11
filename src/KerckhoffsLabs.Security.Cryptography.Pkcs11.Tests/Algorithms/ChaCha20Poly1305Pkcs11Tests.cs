using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-free tests: ctor null-guard and the static size contracts. The BCL
/// <see cref="System.Security.Cryptography.ChaCha20Poly1305"/> does not expose nonce/tag
/// <c>KeySizes</c>, so the adapter defines them per RFC 8439 (12-byte nonce, 16-byte tag) and
/// these tests pin that contract.
/// </summary>
public sealed class ChaCha20Poly1305Pkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new ChaCha20Poly1305Pkcs11(key: null!));

    [Fact]
    public void NonceByteSizes_IsExactlyTwelve()
    {
        var ns = ChaCha20Poly1305Pkcs11.NonceByteSizes;
        Assert.Equal(12, ns.MinSize);
        Assert.Equal(12, ns.MaxSize);
        Assert.Equal(1, ns.SkipSize);
    }

    [Fact]
    public void TagByteSizes_IsExactlySixteen()
    {
        var ts = ChaCha20Poly1305Pkcs11.TagByteSizes;
        Assert.Equal(16, ts.MinSize);
        Assert.Equal(16, ts.MaxSize);
        Assert.Equal(1, ts.SkipSize);
    }
}

[Collection("SoftHsm")]
public sealed class ChaCha20Poly1305Pkcs11Tests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;
    // The whole ChaCha20 family (key type AND mechanism) is absent from the SoftHSM build we ship,
    // so even constructing the adapter (which needs a CKK_CHACHA20 key) is impossible here. Tests
    // that only need a key are gated on the key-type flag; tests that need real crypto are gated on
    // the mechanism flag. Both are false today, so these skip — but they are ready for a backend
    // (or a future SoftHSM) that implements ChaCha20.
    public static bool SoftHsmSupportsChaCha20KeyType => SoftHsmBackendFixture.SoftHsmSupportsChaCha20KeyType;
    public static bool SoftHsmSupportsChaCha20Poly1305 => SoftHsmBackendFixture.SoftHsmSupportsChaCha20Poly1305;

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
            workspace.Session.DestroyObject(k.PrivateHandle);
            k.Dispose();
        }
    }

    // Generates an ephemeral ChaCha20 key, wraps it as the adapter, runs the body, then destroys
    // the key. Uses CKM_GENERIC_SECRET_KEY_GEN because CKM_CHACHA20_KEY_GEN is not in PKCS#11 2.40.
    private void WithChaCha(Action<ChaCha20Poly1305Pkcs11> body)
    {
        using var workspace = OpenWorkspace();
        string label = $"chacha-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_CHACHA20)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), [.. t.Attributes]);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var chacha = new ChaCha20Poly1305Pkcs11(key);
            body(chacha);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // Imports a known ChaCha20 key (by value) so a deterministic vector can be checked.
    private void WithImportedChaCha(byte[] rawKey, Action<ChaCha20Poly1305Pkcs11> body)
    {
        using var workspace = OpenWorkspace();
        string label = $"chacha-kat-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_CHACHA20)
            .Label(label).Value(rawKey).Encrypt().Decrypt().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var chacha = new ChaCha20Poly1305Pkcs11(key);
            body(chacha);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Construction (executes — only needs a non-ChaCha key) =============

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonChaChaKey_Throws()
    {
        using var workspace = OpenWorkspace();
        string label = $"chacha-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), [.. t.Attributes]);
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

    [ConditionalTheory(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20KeyType))]
    [InlineData(8)]   // below the fixed 12-byte nonce
    [InlineData(13)]  // above it
    public void Encrypt_InvalidNonceLength_Throws(int nonceLength) => WithChaCha(chacha =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            chacha.Encrypt(new byte[nonceLength], new byte[8], new byte[8], new byte[16]));
        Assert.Equal("nonce", ex.ParamName);
    });

    [ConditionalTheory(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20KeyType))]
    [InlineData(8)]
    [InlineData(13)]
    public void Decrypt_InvalidNonceLength_Throws(int nonceLength) => WithChaCha(chacha =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            chacha.Decrypt(new byte[nonceLength], new byte[8], new byte[16], new byte[8]));
        Assert.Equal("nonce", ex.ParamName);
    });

    [ConditionalTheory(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20KeyType))]
    [InlineData(12)]  // below the fixed 16-byte tag
    [InlineData(17)]  // above it
    public void Encrypt_InvalidTagLength_Throws(int tagLength) => WithChaCha(chacha =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            chacha.Encrypt(new byte[12], new byte[8], new byte[8], new byte[tagLength]));
        Assert.Equal("tagLength", ex.ParamName);
    });

    [ConditionalTheory(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20KeyType))]
    [InlineData(12)]
    [InlineData(17)]
    public void Decrypt_InvalidTagLength_Throws(int tagLength) => WithChaCha(chacha =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            chacha.Decrypt(new byte[12], new byte[8], new byte[tagLength], new byte[8]));
        Assert.Equal("tagLength", ex.ParamName);
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20KeyType))]
    public void Encrypt_CiphertextLengthMismatch_Throws() => WithChaCha(chacha =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            chacha.Encrypt(new byte[12], new byte[8], new byte[7], new byte[16]));
        Assert.Equal("ciphertext", ex.ParamName);
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20KeyType))]
    public void Decrypt_PlaintextLengthMismatch_Throws() => WithChaCha(chacha =>
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            chacha.Decrypt(new byte[12], new byte[8], new byte[16], new byte[7]));
        Assert.Equal("plaintext", ex.ParamName);
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20KeyType))]
    public void Encrypt_AfterDispose_Throws() => WithChaCha(chacha =>
    {
        chacha.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            chacha.Encrypt(new byte[12], new byte[8], new byte[8], new byte[16]));
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20KeyType))]
    public void Decrypt_AfterDispose_Throws() => WithChaCha(chacha =>
    {
        chacha.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            chacha.Decrypt(new byte[12], new byte[8], new byte[16], new byte[8]));
    });

    // === Real crypto (needs the ChaCha20-Poly1305 mechanism) ===============

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20Poly1305))]
    public void EncryptDecrypt_RoundTrips_WithAad() => WithChaCha(chacha =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("chacha round trip");
        byte[] aad = System.Text.Encoding.UTF8.GetBytes("associated-data");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        chacha.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        byte[] decrypted = new byte[plaintext.Length];
        chacha.Decrypt(nonce, ciphertext, tag, decrypted, aad);

        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext); // sanity: data was actually transformed
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20Poly1305))]
    public void EncryptDecrypt_RoundTrips_NoAad() => WithChaCha(chacha =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("no associated data");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        chacha.Encrypt(nonce, plaintext, ciphertext, tag);
        byte[] decrypted = new byte[plaintext.Length];
        chacha.Decrypt(nonce, ciphertext, tag, decrypted);

        Assert.Equal(plaintext, decrypted);
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20Poly1305))]
    public void Decrypt_TamperedTag_Throws() => WithChaCha(chacha =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("authenticity");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        chacha.Encrypt(nonce, plaintext, ciphertext, tag);
        tag[0] ^= 0xFF;

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Exception>(() => chacha.Decrypt(nonce, ciphertext, tag, dest));
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20Poly1305))]
    public void Decrypt_TamperedCiphertext_Throws() => WithChaCha(chacha =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("integrity matters");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        chacha.Encrypt(nonce, plaintext, ciphertext, tag);
        ciphertext[0] ^= 0xFF;

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Exception>(() => chacha.Decrypt(nonce, ciphertext, tag, dest));
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20Poly1305))]
    public void Decrypt_WrongAad_Throws() => WithChaCha(chacha =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("bound to its aad");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        chacha.Encrypt(nonce, plaintext, ciphertext, tag, System.Text.Encoding.UTF8.GetBytes("aad-A"));

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Exception>(() =>
            chacha.Decrypt(nonce, ciphertext, tag, dest, System.Text.Encoding.UTF8.GetBytes("aad-B")));
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20Poly1305))]
    public void Decrypt_WrongNonce_Throws() => WithChaCha(chacha =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("nonce bound");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        chacha.Encrypt(nonce, plaintext, ciphertext, tag);
        byte[] wrongNonce = Iota(12);
        wrongNonce[0] ^= 0xFF;

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Exception>(() => chacha.Decrypt(wrongNonce, ciphertext, tag, dest));
    });

    // Known-answer test: RFC 8439 section 2.8.2. Expected bytes were also confirmed via the BCL
    // ChaCha20Poly1305 primitive (independent reference).
    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20Poly1305))]
    public void Encrypt_KnownAnswer_MatchesReferenceVector()
    {
        byte[] key = H("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = H("070000004041424344454647");
        byte[] aad = H("50515253c0c1c2c3c4c5c6c7");
        byte[] pt = System.Text.Encoding.ASCII.GetBytes(
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
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
}
