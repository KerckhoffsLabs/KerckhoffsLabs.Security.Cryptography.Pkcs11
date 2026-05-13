using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class AesCcmPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new AesCcmPkcs11(key: null!));
}

[Collection("SoftHsm")]
public sealed class AesCcmPkcs11Tests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public AesCcmPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptDecrypt_RoundTrips_WithAad()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"ccm-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t.Attributes.ToList());
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var ccm = new AesCcmPkcs11(key);

            byte[] nonce = new byte[12];
            for (int i = 0; i < nonce.Length; i++) nonce[i] = (byte)i;
            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("AES-CCM round trip");
            byte[] aad = System.Text.Encoding.UTF8.GetBytes("associated-data");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            ccm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

            byte[] decrypted = new byte[plaintext.Length];
            ccm.Decrypt(nonce, ciphertext, tag, decrypted, aad);

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

        string label = $"ccm-shorttag-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t.Attributes.ToList());
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var ccm = new AesCcmPkcs11(key);

            byte[] nonce = new byte[12];
            byte[] plaintext = new byte[8];
            byte[] ciphertext = new byte[8];
            byte[] shortTag = new byte[2]; // 2 bytes — below MinSize=4

            Assert.Throws<ArgumentException>(() =>
                ccm.Encrypt(nonce, plaintext, ciphertext, shortTag));
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

        string label = $"ccm-badnonce-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t.Attributes.ToList());
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var ccm = new AesCcmPkcs11(key);

            byte[] shortNonce = new byte[6]; // BCL requires 7-13; 6 is below MinSize
            byte[] plaintext = new byte[8];
            byte[] ciphertext = new byte[8];
            byte[] tag = new byte[16];

            Assert.Throws<ArgumentException>(() =>
                ccm.Encrypt(shortNonce, plaintext, ciphertext, tag));
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
    public void Encrypt_TagWrongStep_Throws()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

        string label = $"ccm-tagstep-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t.Attributes.ToList());
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var ccm = new AesCcmPkcs11(key);

            byte[] nonce = new byte[12];
            byte[] plaintext = new byte[8];
            byte[] ciphertext = new byte[8];
            byte[] oddTag = new byte[5]; // 5 bytes — in [4,16] but violates SkipSize=2

            Assert.Throws<ArgumentException>(() =>
                ccm.Encrypt(nonce, plaintext, ciphertext, oddTag));
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

        string label = $"ccm-tamper-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t.Attributes.ToList());
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var ccm = new AesCcmPkcs11(key);

            byte[] nonce = new byte[12];
            for (int i = 0; i < nonce.Length; i++) nonce[i] = (byte)i;
            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("authenticity");
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            ccm.Encrypt(nonce, plaintext, ciphertext, tag);

            // Tamper one byte of the tag
            tag[0] ^= 0xFF;

            byte[] dest = new byte[plaintext.Length];
            Assert.ThrowsAny<Exception>(() => ccm.Decrypt(nonce, ciphertext, tag, dest));
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
