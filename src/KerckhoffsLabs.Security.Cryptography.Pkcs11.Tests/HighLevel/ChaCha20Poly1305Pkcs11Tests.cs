using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class ChaCha20Poly1305Pkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new ChaCha20Poly1305Pkcs11(key: null!));
}

[Collection("SoftHsm")]
public sealed class ChaCha20Poly1305Pkcs11Tests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public ChaCha20Poly1305Pkcs11Tests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    // Helper: generate a ChaCha20 key under a unique label and return the label.
    // Caller is responsible for cleanup. Uses CKM_GENERIC_SECRET_KEY_GEN because
    // CKM_CHACHA20_KEY_GEN is not defined in PKCS#11 2.40 / SoftHSM.
    private string GenerateChaCha20Key(Pkcs11Workspace workspace)
    {
        string label = $"chacha-{Guid.NewGuid():N}";
        using var t = ObjectTemplate.ForSecretKey(CKK.CKK_CHACHA20)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build();
        workspace.Session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t.Attributes.ToList());
        return label;
    }

    private static void DestroyKeysByLabel(Pkcs11Workspace workspace, string label)
    {
        using var f = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(f))
        {
            workspace.Session.DestroyObject(k.PrivateHandle);
            k.Dispose();
        }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptDecrypt_RoundTrips_WithAad()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = GenerateChaCha20Key(workspace);
        try
        {
            using var key = workspace.OpenKey(label);
            using var chacha = new ChaCha20Poly1305Pkcs11(key);

            byte[] nonce = new byte[12];
            for (int i = 0; i < nonce.Length; i++) nonce[i] = (byte)i;
            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("chacha round trip");
            byte[] aad = System.Text.Encoding.UTF8.GetBytes("associated-data");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            chacha.Encrypt(nonce, plaintext, ciphertext, tag, aad);

            byte[] decrypted = new byte[plaintext.Length];
            chacha.Decrypt(nonce, ciphertext, tag, decrypted, aad);

            Assert.Equal(plaintext, decrypted);
        }
        finally
        {
            DestroyKeysByLabel(workspace, label);
        }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decrypt_TamperedTag_Throws()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = GenerateChaCha20Key(workspace);
        try
        {
            using var key = workspace.OpenKey(label);
            using var chacha = new ChaCha20Poly1305Pkcs11(key);

            byte[] nonce = new byte[12];
            for (int i = 0; i < nonce.Length; i++) nonce[i] = (byte)i;
            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("authenticity");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            chacha.Encrypt(nonce, plaintext, ciphertext, tag);

            // Tamper one byte of the tag — authentication must fail.
            tag[0] ^= 0xFF;

            byte[] dest = new byte[plaintext.Length];
            Assert.ThrowsAny<Exception>(() => chacha.Decrypt(nonce, ciphertext, tag, dest));
        }
        finally
        {
            DestroyKeysByLabel(workspace, label);
        }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Encrypt_NonceWrongLength_Throws()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = GenerateChaCha20Key(workspace);
        try
        {
            using var key = workspace.OpenKey(label);
            using var chacha = new ChaCha20Poly1305Pkcs11(key);

            // ChaCha20-Poly1305 requires exactly 12-byte nonce.
            byte[] shortNonce = new byte[8];
            byte[] plaintext = new byte[8];
            byte[] ciphertext = new byte[8];
            byte[] tag = new byte[16];

            Assert.Throws<ArgumentException>(() =>
                chacha.Encrypt(shortNonce, plaintext, ciphertext, tag));
        }
        finally
        {
            DestroyKeysByLabel(workspace, label);
        }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Encrypt_TagWrongLength_Throws()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = GenerateChaCha20Key(workspace);
        try
        {
            using var key = workspace.OpenKey(label);
            using var chacha = new ChaCha20Poly1305Pkcs11(key);

            // ChaCha20-Poly1305 requires exactly 16-byte tag.
            byte[] nonce = new byte[12];
            byte[] plaintext = new byte[8];
            byte[] ciphertext = new byte[8];
            byte[] shortTag = new byte[8]; // 64 bits — outside the fixed 128-bit size

            Assert.Throws<ArgumentException>(() =>
                chacha.Encrypt(nonce, plaintext, ciphertext, shortTag));
        }
        finally
        {
            DestroyKeysByLabel(workspace, label);
        }
    }
}
