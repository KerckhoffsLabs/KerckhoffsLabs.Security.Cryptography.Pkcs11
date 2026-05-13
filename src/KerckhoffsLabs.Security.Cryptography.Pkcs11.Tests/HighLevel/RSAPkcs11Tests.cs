using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class RSAPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new RSAPkcs11(key: null!));
    }
}

[Collection("SoftHsm")]
public sealed class RSAPkcs11Tests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public RSAPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignVerify_Sha256_Pkcs1_RoundTrips()
    {
        using var workspace = OpenWorkspace();
        using var key = GenerateRsaKey(workspace, out var pubH, out var privH);
        try
        {
            using var rsa = new RSAPkcs11(key);
            byte[] data = System.Text.Encoding.UTF8.GetBytes("test");
            byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            data[0] ^= 0xFF;
            Assert.False(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
        finally { Cleanup(workspace, pubH, privH); }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignVerify_Sha256_Pss_RoundTrips()
    {
        using var workspace = OpenWorkspace();
        using var key = GenerateRsaKey(workspace, out var pubH, out var privH);
        try
        {
            using var rsa = new RSAPkcs11(key);
            byte[] data = System.Text.Encoding.UTF8.GetBytes("test");
            byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        }
        finally { Cleanup(workspace, pubH, privH); }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptDecrypt_OaepSha256_RoundTrips()
    {
        using var workspace = OpenWorkspace();
        using var key = GenerateRsaKey(workspace, out var pubH, out var privH);
        try
        {
            using var rsa = new RSAPkcs11(key);
            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("secret payload");
            byte[] ct = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
            byte[] recovered = rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA256);
            Assert.Equal(plaintext, recovered);
        }
        finally { Cleanup(workspace, pubH, privH); }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportParameters_PublicOnly_ReturnsModulusAndExponent()
    {
        using var workspace = OpenWorkspace();
        using var key = GenerateRsaKey(workspace, out var pubH, out var privH);
        try
        {
            using var rsa = new RSAPkcs11(key);
            var p = rsa.ExportParameters(includePrivateParameters: false);
            Assert.NotNull(p.Modulus);
            Assert.NotNull(p.Exponent);
            Assert.Equal(2048 / 8, p.Modulus!.Length);
            Assert.Null(p.D); // private parts must not be set
        }
        finally { Cleanup(workspace, pubH, privH); }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportParameters_Private_ThrowsInsecureOperation()
    {
        using var workspace = OpenWorkspace();
        using var key = GenerateRsaKey(workspace, out var pubH, out var privH);
        try
        {
            using var rsa = new RSAPkcs11(key);
            Assert.Throws<InsecureOperationException>(() => rsa.ExportParameters(includePrivateParameters: true));
        }
        finally { Cleanup(workspace, pubH, privH); }
    }

    private static Pkcs11Key GenerateRsaKey(Pkcs11Workspace workspace,
        out KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.ObjectHandle pubH,
        out KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.ObjectHandle privH)
    {
        string label = $"rsa-prov-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().Encrypt().ModulusBits(2048)
            .PublicExponent(new byte[] { 0x01, 0x00, 0x01 }).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Decrypt().Build();

        var key = workspace.GenerateKey(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), privTpl, pubTpl);
        pubH = key.PublicHandle;
        privH = key.PrivateHandle;
        return key;
    }

    private static void Cleanup(Pkcs11Workspace workspace,
        KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.ObjectHandle pubH,
        KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.ObjectHandle privH)
    {
        if (!pubH.IsInvalid)  workspace.Session.DestroyObject(pubH);
        if (!privH.IsInvalid) workspace.Session.DestroyObject(privH);
    }
}
