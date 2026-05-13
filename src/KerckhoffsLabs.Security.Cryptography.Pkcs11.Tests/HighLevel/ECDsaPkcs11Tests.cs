using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Security;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

public sealed class ECDsaPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new ECDsaPkcs11(key: null!));
}

[Collection("SoftHsm")]
public sealed class ECDsaPkcs11Tests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public ECDsaPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend) => _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignVerify_Sha256_RoundTrips()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));
        using var key = GenerateP256Key(workspace, out var pubH, out var privH);
        try
        {
            using var ec = new ECDsaPkcs11(key);
            byte[] data = System.Text.Encoding.UTF8.GetBytes("ecdsa test");
            byte[] sig = ec.SignData(data, HashAlgorithmName.SHA256);
            Assert.True(ec.VerifyData(data, sig, HashAlgorithmName.SHA256));
            data[0] ^= 0xFF;
            Assert.False(ec.VerifyData(data, sig, HashAlgorithmName.SHA256));
        }
        finally
        {
            if (!pubH.IsInvalid)  workspace.Session.DestroyObject(pubH);
            if (!privH.IsInvalid) workspace.Session.DestroyObject(privH);
        }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint()
    {
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));
        using var key = GenerateP256Key(workspace, out var pubH, out var privH);
        try
        {
            using var ec = new ECDsaPkcs11(key);
            var p = ec.ExportParameters(includePrivateParameters: false);
            Assert.Equal(ECCurve.NamedCurves.nistP256.Oid.Value, p.Curve.Oid.Value);
            Assert.NotNull(p.Q.X);
            Assert.NotNull(p.Q.Y);
            Assert.Null(p.D); // private parts must not be set
        }
        finally
        {
            if (!pubH.IsInvalid)  workspace.Session.DestroyObject(pubH);
            if (!privH.IsInvalid) workspace.Session.DestroyObject(privH);
        }
    }

    private static Pkcs11Key GenerateP256Key(Pkcs11Workspace workspace,
        out ObjectHandle pubH, out ObjectHandle privH)
    {
        string label = $"ec-prov-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);
        byte[] p256Oid = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).Verify().EcParams(p256Oid).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(id).Sign().Build();

        var key = workspace.GenerateKey(
            new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), privTpl, pubTpl);
        pubH = key.PublicHandle;
        privH = key.PrivateHandle;
        return key;
    }
}
