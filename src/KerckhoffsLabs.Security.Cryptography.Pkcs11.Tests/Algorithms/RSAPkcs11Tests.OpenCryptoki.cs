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

    // Key sizes against a second real backend. RSA < 2048 is gated behind AllowInsecure (NIST SP
    // 800-131A), so the 1024 case generates under an opt-in scope; 2048/3072/4096 need no opt-in.
    [ConditionalTheory(nameof(Available))]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    public void SignVerifyData_AcrossKeySizes_RoundTrips(int modulusBits)
    {
        Require(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS_PSS);
        using var workspace = OpenWorkspace();
        using IDisposable? insecure = modulusBits < 2048 ? workspace.AllowInsecureScope() : null;
        string label = $"octk-rsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().Encrypt().ModulusBits(modulusBits)
            .PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Decrypt().Build();
        var key = workspace.GenerateKey(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var rsa = new RSAPkcs11(key);
            byte[] data = Encoding.UTF8.GetBytes($"rsa-{modulusBits} payload");
            byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            Assert.Equal(modulusBits / 8, sig.Length);
            Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

            var pub = rsa.ExportParameters(includePrivateParameters: false);
            Assert.Equal(modulusBits / 8, pub.Modulus!.Length);
            using var bcl = RSA.Create();
            bcl.ImportParameters(pub);
            Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

            sig[0] ^= 0xFF;
            Assert.False(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        }
        finally
        {
            try { DestroyByLabel(workspace, label); } catch { /* best-effort */ }
            key.Dispose();
        }
    }

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

    // A ciphertext produced under a different key pair must not decrypt under this key: the OAEP
    // padding check rejects it instead of yielding plaintext (mirrors the SoftHSM wrong-key test).
    [ConditionalFact(nameof(Available))]
    public void Decrypt_OaepCiphertextFromDifferentKey_Throws() => WithRsa((workspace, rsa) =>
    {
        Require(CKM.CKM_RSA_PKCS_OAEP);
        string otherLabel = $"octk-rsa-other-{Guid.NewGuid():N}";
        byte[] otherId = Encoding.ASCII.GetBytes(otherLabel);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(otherLabel).Id(otherId).Encrypt().ModulusBits(2048)
            .PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(otherLabel).Id(otherId).Decrypt().Build();
        var otherKey = workspace.GenerateKey(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var otherRsa = new RSAPkcs11(otherKey);
            byte[] ct = otherRsa.Encrypt(Encoding.UTF8.GetBytes("for the other key"), RSAEncryptionPadding.OaepSHA1);
            Assert.ThrowsAny<Pkcs11Exception>(() => rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA1));
        }
        finally
        {
            try { DestroyByLabel(workspace, otherLabel); } catch { /* best-effort */ }
            otherKey.Dispose();
        }
    });
}
