using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// RSA against the second real backend (opencryptoki): PKCS#1 v1.5 and PSS signatures and OAEP
/// encryption, mirroring the SoftHSM coverage for the mechanisms opencryptoki implements.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class RSAPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private void Require(params CKM[] mechanisms)
    {
        foreach (var m in mechanisms)
            if (!_backend.Supports(m))
                throw new SkipTestException($"opencryptoki: {m} not available");
    }

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter)) { k.Delete(); k.Dispose(); }
    }

    private void WithRsa(Action<Pkcs11Workspace, RSAPkcs11> body)
    {
        Require(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        using var workspace = OpenWorkspace();
        string label = $"octk-rsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().Encrypt().ModulusBits(2048)
            .PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Decrypt().Build();
        var key = workspace.GenerateKey(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var rsa = new RSAPkcs11(key);
            body(workspace, rsa);
        }
        finally
        {
            try { DestroyByLabel(workspace, label); } catch { /* best-effort */ }
            key.Dispose();
        }
    }

    [ConditionalFact(nameof(Available))]
    public void SignVerifyData_Pkcs1Sha256_RoundTrips() => WithRsa((_, rsa) =>
    {
        Require(CKM.CKM_SHA256_RSA_PKCS);
        byte[] data = Encoding.UTF8.GetBytes("opencryptoki rsa pkcs1");
        byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        data[0] ^= 0xFF;
        Assert.False(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    });

    [ConditionalFact(nameof(Available))]
    public void SignVerifyData_PssSha256_RoundTrips() => WithRsa((_, rsa) =>
    {
        Require(CKM.CKM_SHA256_RSA_PKCS_PSS);
        byte[] data = Encoding.UTF8.GetBytes("opencryptoki rsa pss");
        byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        sig[0] ^= 0xFF;
        Assert.False(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    });

    [ConditionalFact(nameof(Available))]
    public void EncryptDecrypt_OaepSha1_RoundTrips_AndRejectsTamper() => WithRsa((_, rsa) =>
    {
        Require(CKM.CKM_RSA_PKCS_OAEP);
        byte[] plaintext = Encoding.UTF8.GetBytes("opencryptoki rsa oaep");
        byte[] ct = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA1);
        Assert.Equal(plaintext, rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA1));

        ct[ct.Length / 2] ^= 0xFF;
        Assert.ThrowsAny<Pkcs11Exception>(() => rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA1));
    });
}
