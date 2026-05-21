using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

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

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void SignVerify_RoundTrips(string curve)
    {
        var (oid, hash, _) = Spec(curve);
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));
        using var key = GenerateEcKey(workspace, oid, out var pubH, out var privH);
        try
        {
            using var ec = new ECDsaPkcs11(key);
            byte[] data = System.Text.Encoding.UTF8.GetBytes("ecdsa test");
            byte[] sig = ec.SignData(data, hash);
            Assert.True(ec.VerifyData(data, sig, hash));
            data[0] ^= 0xFF;
            Assert.False(ec.VerifyData(data, sig, hash));
        }
        finally
        {
            if (!pubH.IsInvalid) workspace.Session.DestroyObject(pubH);
            if (!privH.IsInvalid) workspace.Session.DestroyObject(privH);
        }
    }

    // BL-038: cross-library verification. Export the public key, rebuild an ECDsa from it, and
    // verify the PKCS#11 signature with the BCL — catches a wrong named-curve OID or a mangled
    // point in ExportParameters that a same-instance round-trip would not. CKM_ECDSA emits raw
    // r||s, so the BCL must interpret the signature as IEEE P1363.
    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void SignData_VerifiesUnderBclFromExportedPublicKey(string curve)
    {
        var (oid, hash, _) = Spec(curve);
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));
        using var key = GenerateEcKey(workspace, oid, out var pubH, out var privH);
        try
        {
            using var ec = new ECDsaPkcs11(key);
            byte[] data = System.Text.Encoding.UTF8.GetBytes("cross-library verify");
            byte[] sig = ec.SignData(data, hash);

            using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));
            Assert.True(bcl.VerifyData(data, sig, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }
        finally
        {
            if (!pubH.IsInvalid) workspace.Session.DestroyObject(pubH);
            if (!privH.IsInvalid) workspace.Session.DestroyObject(privH);
        }
    }

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint(string curve)
    {
        var (oid, _, expectedOidValue) = Spec(curve);
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));
        using var key = GenerateEcKey(workspace, oid, out var pubH, out var privH);
        try
        {
            using var ec = new ECDsaPkcs11(key);
            var p = ec.ExportParameters(includePrivateParameters: false);
            Assert.Equal(expectedOidValue, p.Curve.Oid.Value);
            Assert.NotNull(p.Q.X);
            Assert.NotNull(p.Q.Y);
            Assert.Null(p.D); // private parts must not be set
        }
        finally
        {
            if (!pubH.IsInvalid) workspace.Session.DestroyObject(pubH);
            if (!privH.IsInvalid) workspace.Session.DestroyObject(privH);
        }
    }

    // Curve under test -> (CKA_EC_PARAMS OID, hash paired with the curve, expected exported OID value).
    private static (byte[] oid, HashAlgorithmName hash, string? expectedOidValue) Spec(string curve) => curve switch
    {
        "P-256" => (TestKeys.EcP256Oid, HashAlgorithmName.SHA256, ECCurve.NamedCurves.nistP256.Oid.Value),
        "P-384" => (TestKeys.EcP384Oid, HashAlgorithmName.SHA384, ECCurve.NamedCurves.nistP384.Oid.Value),
        "P-521" => (TestKeys.EcP521Oid, HashAlgorithmName.SHA512, ECCurve.NamedCurves.nistP521.Oid.Value),
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unknown EC curve."),
    };

    private static Pkcs11Key GenerateEcKey(Pkcs11Workspace workspace, byte[] ecOid,
        out ObjectHandle pubH, out ObjectHandle privH)
    {
        string label = $"ec-prov-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).Verify().EcParams(ecOid).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(id).Sign().Build();

        var key = workspace.GenerateKey(
            new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), privTpl, pubTpl);
        pubH = key.PublicHandle;
        privH = key.PrivateHandle;
        return key;
    }
}
