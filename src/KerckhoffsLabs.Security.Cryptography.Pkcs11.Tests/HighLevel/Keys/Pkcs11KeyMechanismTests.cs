using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Keys;

internal static class Pkcs11KeyMechanismCases
{
    public static void Assert_AesCbcEncryptDecrypt_RoundTrips(Pkcs11Workspace workspace)
    {
        byte[] iv = new byte[16];
        for (int i = 0; i < iv.Length; i++) iv[i] = (byte)i;
        byte[] plaintext = new byte[32];
        for (int i = 0; i < plaintext.Length; i++) plaintext[i] = (byte)(0x40 + i);

        string label = $"aes-cbc-{Guid.NewGuid():N}";
        using var labeledTpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build();
        workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN),
            [.. labeledTpl.Attributes]);

        try
        {
            using var key = workspace.OpenKey(label);
            var mech = new Mechanism(CKM.CKM_AES_CBC, iv);

            // Raw AES-CBC is gated by default; this test deliberately exercises it.
            using var _ = workspace.AllowInsecureScope();
            byte[] ciphertext = key.Encrypt(mech, plaintext);
            byte[] recovered = key.Decrypt(mech, ciphertext);

            Assert.Equal(plaintext, recovered);
        }
        finally
        {
            using var filter = ObjectTemplate.Empty().Label(label).Build();
            foreach (var k in workspace.FindKeys(filter))
            {
                var handle = k.PrivateHandle.IsInvalid ? k.PublicHandle : k.PrivateHandle;
                workspace.Session.DestroyObject(handle);
                k.Dispose();
            }
        }
    }

    public static void Assert_RsaSignVerify_RoundTrips(Pkcs11Workspace workspace)
    {
        string label = $"sign-verify-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);
        byte[] data = System.Text.Encoding.UTF8.GetBytes("hello pkcs11");

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048)
            .PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Build();

        workspace.Session.GenerateKeyPair(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
            [.. pubTpl.Attributes],
            [.. privTpl.Attributes],
            out var pubHandle,
            out var privHandle);

        try
        {
            using var key = workspace.OpenKey(label);
            var sha256Rsa = new Mechanism(CKM.CKM_SHA256_RSA_PKCS);

            byte[] signature = key.Sign(sha256Rsa, data);
            Assert.True(key.Verify(sha256Rsa, data, signature));

            byte[] tampered = (byte[])data.Clone();
            tampered[0] ^= 0xFF;
            Assert.False(key.Verify(sha256Rsa, tampered, signature));
        }
        finally
        {
            workspace.Session.DestroyObject(pubHandle);
            workspace.Session.DestroyObject(privHandle);
        }
    }

    public static void Assert_AesKeyWrapUnwrap_RoundTrips(Pkcs11Workspace workspace)
    {
        string wrapperLabel = $"wrapper-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(wrapperLabel).ValueLen(32).Wrap().Unwrap().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN),
                [.. t.Attributes]);
        }

        string targetLabel = $"target-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(targetLabel).ValueLen(16).Encrypt().Decrypt().Extractable().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN),
                [.. t.Attributes]);
        }

        try
        {
            using var wrapper = workspace.OpenKey(wrapperLabel);
            using var target = workspace.OpenKey(targetLabel);

            byte[] wrapped = wrapper.Wrap(new Mechanism(CKM.CKM_AES_KEY_WRAP), target);

            // No .Extractable(): the unwrap secure-default (CKA_EXTRACTABLE=false) is fine here —
            // the assertions only check the handle and key type, not the key value.
            using var unwrapTpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
                .Encrypt().Decrypt().Build();
            using var unwrapped = wrapper.Unwrap(
                new Mechanism(CKM.CKM_AES_KEY_WRAP), wrapped, unwrapTpl);

            Assert.False(unwrapped.PrivateHandle.IsInvalid);
            Assert.Equal(CKK.CKK_AES, unwrapped.KeyType);
        }
        finally
        {
            CleanupByLabel(workspace, wrapperLabel);
            CleanupByLabel(workspace, targetLabel);
        }
    }

    private static void CleanupByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            var handle = k.PrivateHandle.IsInvalid ? k.PublicHandle : k.PrivateHandle;
            workspace.Session.DestroyObject(handle);
            k.Dispose();
        }
    }
}

[Collection("SoftHsm")]
public sealed class Pkcs11KeyMechanismTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaPkcs_SignVerify_RoundTrip()
    {
        using var workspace = OpenWorkspace();
        Pkcs11KeyMechanismCases.Assert_RsaSignVerify_RoundTrips(workspace);
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesCbc_EncryptDecrypt_RoundTrip()
    {
        using var workspace = OpenWorkspace();
        Pkcs11KeyMechanismCases.Assert_AesCbcEncryptDecrypt_RoundTrips(workspace);
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesKeyWrap_WrapUnwrap_RoundTrip()
    {
        using var workspace = OpenWorkspace();
        Pkcs11KeyMechanismCases.Assert_AesKeyWrapUnwrap_RoundTrips(workspace);
    }
}
