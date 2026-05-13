using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class AesGcmPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new AesGcmPkcs11(key: null!));
}

[Collection("SoftHsm")]
public sealed class AesGcmPkcs11Tests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public AesGcmPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptDecrypt_RoundTrips_WithAad()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"gcm-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t.Attributes.ToList());
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var gcm = new AesGcmPkcs11(key);

            byte[] nonce = new byte[12];
            for (int i = 0; i < nonce.Length; i++) nonce[i] = (byte)i;
            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("AES-GCM round trip");
            byte[] aad = System.Text.Encoding.UTF8.GetBytes("associated-data");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

            byte[] decrypted = new byte[plaintext.Length];
            gcm.Decrypt(nonce, ciphertext, tag, decrypted, aad);

            Assert.Equal(plaintext, decrypted);
        }
        finally
        {
            using var f = ObjectTemplate.Empty().Label(label).Build();
            foreach (var k in workspace.FindKeys(f))
            {
                workspace.Session.DestroyObject(k.PrivateHandle);
                k.Dispose();
            }
        }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Encrypt_TagTooShort_Throws()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"gcm-shorttag-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t.Attributes.ToList());
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var gcm = new AesGcmPkcs11(key);

            byte[] nonce = new byte[12];
            byte[] plaintext = new byte[8];
            byte[] ciphertext = new byte[8];
            byte[] shortTag = new byte[8]; // 64 bits — outside BCL valid range

            Assert.Throws<ArgumentException>(() =>
                gcm.Encrypt(nonce, plaintext, ciphertext, shortTag));
        }
        finally
        {
            using var f = ObjectTemplate.Empty().Label(label).Build();
            foreach (var k in workspace.FindKeys(f))
            {
                workspace.Session.DestroyObject(k.PrivateHandle);
                k.Dispose();
            }
        }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Encrypt_NonceWrongLength_Throws()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"gcm-badnonce-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t.Attributes.ToList());
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var gcm = new AesGcmPkcs11(key);

            byte[] shortNonce = new byte[8]; // BCL requires exactly 12
            byte[] plaintext = new byte[8];
            byte[] ciphertext = new byte[8];
            byte[] tag = new byte[16];

            Assert.Throws<ArgumentException>(() =>
                gcm.Encrypt(shortNonce, plaintext, ciphertext, tag));
        }
        finally
        {
            using var f = ObjectTemplate.Empty().Label(label).Build();
            foreach (var k in workspace.FindKeys(f))
            {
                workspace.Session.DestroyObject(k.PrivateHandle);
                k.Dispose();
            }
        }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decrypt_TamperedTag_Throws()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"gcm-tamper-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t.Attributes.ToList());
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var gcm = new AesGcmPkcs11(key);

            byte[] nonce = new byte[12];
            for (int i = 0; i < nonce.Length; i++) nonce[i] = (byte)i;
            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("authenticity");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            gcm.Encrypt(nonce, plaintext, ciphertext, tag);

            // Tamper one byte of the tag
            tag[0] ^= 0xFF;

            byte[] dest = new byte[plaintext.Length];
            Assert.ThrowsAny<Exception>(() => gcm.Decrypt(nonce, ciphertext, tag, dest));
        }
        finally
        {
            using var f = ObjectTemplate.Empty().Label(label).Build();
            foreach (var k in workspace.FindKeys(f))
            {
                workspace.Session.DestroyObject(k.PrivateHandle);
                k.Dispose();
            }
        }
    }
}
