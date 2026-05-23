using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Adapters.Tests;

public sealed class ECDsaPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new ECDsaPkcs11(key: null!));
}

[Collection("SoftHsm")]
public sealed class ECDsaPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    // Curve under test -> (CKA_EC_PARAMS OID, hash paired with the curve, expected exported OID value).
    private static (byte[] oid, HashAlgorithmName hash, string? expectedOidValue) Spec(string curve) => curve switch
    {
        "P-256" => (TestKeys.EcP256Oid, HashAlgorithmName.SHA256, ECCurve.NamedCurves.nistP256.Oid.Value),
        "P-384" => (TestKeys.EcP384Oid, HashAlgorithmName.SHA384, ECCurve.NamedCurves.nistP384.Oid.Value),
        "P-521" => (TestKeys.EcP521Oid, HashAlgorithmName.SHA512, ECCurve.NamedCurves.nistP521.Oid.Value),
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unknown EC curve."),
    };

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static Pkcs11Key GenerateEcKey(Pkcs11Workspace workspace, byte[] ecOid)
    {
        string label = $"ec-prov-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).Verify().EcParams(ecOid).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(id).Sign().Build();

        return workspace.GenerateKey(
            new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), privTpl, pubTpl);
    }

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    // Generates an EC key pair for the curve, wraps it as ECDsaPkcs11, runs the body with the
    // adapter and the curve-matched hash, then destroys both objects.
    private void WithEcDsa(string curve, Action<ECDsaPkcs11, HashAlgorithmName> body)
    {
        var (oid, hash, _) = Spec(curve);
        using var workspace = OpenWorkspace();
        var key = GenerateEcKey(workspace, oid);
        try
        {
            using var ec = new ECDsaPkcs11(key);
            body(ec, hash);
        }
        finally
        {
            try { key.Delete(); }
            catch { /* best-effort cleanup */ }
            key.Dispose();
        }
    }

    // === Construction =====================================================

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonEcKey_Throws()
    {
        using var workspace = OpenWorkspace();
        string label = $"ec-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            using (var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t)) { }
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new ECDsaPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Sign/verify data — byte[] overloads (BCL hashes managed-side, then SignHash) =======

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void SignVerifyData_RoundTrips(string curve) => WithEcDsa(curve, (ec, hash) =>
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes("ecdsa test");
        byte[] sig = ec.SignData(data, hash);
        Assert.True(ec.VerifyData(data, sig, hash));
        data[0] ^= 0xFF;
        Assert.False(ec.VerifyData(data, sig, hash));
    });

    // === Sign/verify data — span overloads (the adapter's combined on-token hash+sign path) ==

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void TrySignData_Span_VerifyData_Span_RoundTrips(string curve) => WithEcDsa(curve, (ec, hash) =>
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes("combined hash+sign on token");
        byte[] dest = new byte[256];

        Assert.True(ec.TrySignData(data, dest, hash, out int written));
        Assert.True(written > 0);

        var sig = dest.AsSpan(0, written);
        Assert.True(ec.VerifyData(data.AsSpan(), sig, hash));

        byte[] tampered = [.. data];
        tampered[0] ^= 0xFF;
        Assert.False(ec.VerifyData(tampered.AsSpan(), sig, hash));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => WithEcDsa("P-256", (ec, hash) =>
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes("too small destination");
        Assert.False(ec.TrySignData(data, new byte[1], hash, out int written));
        Assert.Equal(0, written);
    });

    // === Sign/verify hash — raw ECDSA, no on-token hashing ==================

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignHash_VerifyHash_RoundTrips() => WithEcDsa("P-256", (ec, _) =>
    {
        byte[] hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("raw ecdsa over a digest"));
        byte[] sig = ec.SignHash(hash);
        Assert.True(ec.VerifyHash(hash, sig));

        hash[0] ^= 0xFF;
        Assert.False(ec.VerifyHash(hash, sig));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignHash_NullHash_Throws() => WithEcDsa("P-256", (ec, _) =>
        Assert.Throws<ArgumentNullException>(() => ec.SignHash(null!)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void VerifyHash_NullArguments_Throw() => WithEcDsa("P-256", (ec, _) =>
    {
        Assert.Throws<ArgumentNullException>(() => ec.VerifyHash(null!, new byte[64]));
        Assert.Throws<ArgumentNullException>(() => ec.VerifyHash(new byte[32], null!));
    });

    // === Key material export ==============================================

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint(string curve)
    {
        var (_, _, expectedOidValue) = Spec(curve);
        WithEcDsa(curve, (ec, _) =>
        {
            var p = ec.ExportParameters(includePrivateParameters: false);
            Assert.Equal(expectedOidValue, p.Curve.Oid.Value);
            Assert.NotNull(p.Q.X);
            Assert.NotNull(p.Q.Y);
            Assert.Null(p.D); // private parts must not be set
        });
    }

    // BL-038: cross-library verification. Export the public key, rebuild an ECDsa from it, and
    // verify the PKCS#11 signature with the BCL — catches a wrong named-curve OID or a mangled
    // point in ExportParameters that a same-instance round-trip would not. CKM_ECDSA emits raw
    // r||s, so the BCL must interpret the signature as IEEE P1363.
    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void SignData_VerifiesUnderBclFromExportedPublicKey(string curve) => WithEcDsa(curve, (ec, hash) =>
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes("cross-library verify");
        byte[] sig = ec.SignData(data, hash);

        using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));
        Assert.True(bcl.VerifyData(data, sig, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportParameters_Private_ThrowsInsecure() => WithEcDsa("P-256", (ec, _) =>
        Assert.Throws<InsecureOperationException>(() => ec.ExportParameters(includePrivateParameters: true)));

    // === Unsupported BCL surface (PKCS#11 keys are token-resident / non-extractable) ========

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportExplicitParameters_Throws() => WithEcDsa("P-256", (ec, _) =>
        Assert.Throws<NotSupportedException>(() => ec.ExportExplicitParameters(includePrivateParameters: false)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ImportParameters_Throws() => WithEcDsa("P-256", (ec, _) =>
        Assert.Throws<NotSupportedException>(() => ec.ImportParameters(default)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateKey_Throws() => WithEcDsa("P-256", (ec, _) =>
        Assert.Throws<NotSupportedException>(() => ec.GenerateKey(ECCurve.NamedCurves.nistP256)));
}
