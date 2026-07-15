using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic ECDsaPkcs11 tests: sign/verify (byte[] + span overloads) cross-verified under the
/// BCL, raw SignHash/VerifyHash, public-parameter export, and the unsupported BCL surface. Curve is a
/// parameter so each wrapper supplies the curves its backend implements (SoftHSM: P-256/384/521;
/// opencryptoki: P-256). Cases skip where the backend lacks EC key-pair generation + ECDSA.
/// </summary>
internal static class ECDsaPkcs11TestCases
{
    // Curve under test -> (CKA_EC_PARAMS OID, hash paired with the curve, expected exported OID value).
    private static (byte[] oid, HashAlgorithmName hash, string? expectedOidValue) Spec(string curve) => curve switch
    {
        "P-256" => (TestKeys.EcP256Oid, HashAlgorithmName.SHA256, BclECCurve.NamedCurves.nistP256.Oid.Value),
        "P-384" => (TestKeys.EcP384Oid, HashAlgorithmName.SHA384, BclECCurve.NamedCurves.nistP384.Oid.Value),
        "P-521" => (TestKeys.EcP521Oid, HashAlgorithmName.SHA512, BclECCurve.NamedCurves.nistP521.Oid.Value),
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unknown EC curve."),
    };

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    private static Pkcs11Key GenerateEcKey(Pkcs11Workspace workspace, byte[] ecOid)
    {
        string label = $"ec-prov-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).Verify().EcParams(ecOid).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(id).Sign().Build();

        return workspace.GenerateKey(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), privTpl, pubTpl);
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
    // curve-matched hash, then destroys the key. Skips where the backend lacks EC keygen / ECDSA.
    private static void WithEcDsa(IPkcs11Backend backend, string curve, Action<ECDsaPkcs11, HashAlgorithmName> body) =>
        WithEcDsa(backend, curve, ec => body(ec, Spec(curve).hash));

    private static void WithEcDsa(IPkcs11Backend backend, string curve, Action<ECDsaPkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_EC_KEY_PAIR_GEN) || !backend.Supports(CKM.CKM_ECDSA))
            throw new SkipTestException("Backend does not advertise CKM_EC_KEY_PAIR_GEN + CKM_ECDSA.");

        var (oid, _, _) = Spec(curve);
        using var workspace = OpenWorkspace(backend);
        var key = GenerateEcKey(workspace, oid);
        try
        {
            using var ec = new ECDsaPkcs11(key);
            body(ec);
        }
        finally
        {
            try { key.Delete(); } catch { /* best-effort cleanup */ }
            key.Dispose();
        }
    }

    internal static void Assert_Ctor_NonEcKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"ec-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new ECDsaPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // Curve × hash matrix: ECDSA signs whatever digest it is handed, so curve and digest are
    // independent. Cross-verify each signature under the BCL from the exported public key (raw r‖s).
    internal static void Assert_SignVerifyData_CurveHashMatrix_RoundTrips(IPkcs11Backend backend, string curve, string hashName) =>
        WithEcDsa(backend, curve, ec =>
        {
            var hash = new HashAlgorithmName(hashName);
            byte[] data = Encoding.UTF8.GetBytes($"ecdsa {curve}/{hashName}");
            byte[] sig = ec.SignData(data, hash);
            Assert.True(ec.VerifyData(data, sig, hash));

            using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));
            Assert.True(bcl.VerifyData(data, sig, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(ec.VerifyData(tampered, sig, hash));
        });

    internal static void Assert_TrySignData_Span_VerifyData_Span_RoundTrips(IPkcs11Backend backend, string curve) =>
        WithEcDsa(backend, curve, (ec, hash) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("combined hash+sign on token");
            byte[] dest = new byte[256];

            Assert.True(ec.TrySignData(data, dest, hash, out int written));
            Assert.True(written > 0);

            var sig = dest.AsSpan(0, written);
            Assert.True(ec.VerifyData(data.AsSpan(), sig, hash));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(ec.VerifyData(tampered.AsSpan(), sig, hash));
        });

    internal static void Assert_TrySignData_DestinationTooSmall_ReturnsFalse(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, hash) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("too small destination");
            Assert.False(ec.TrySignData(data, new byte[1], hash, out int written));
            Assert.Equal(0, written);
        });

    internal static void Assert_SignHash_VerifyHash_RoundTrips(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
        {
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("raw ecdsa over a digest"));
            byte[] sig = ec.SignHash(hash);
            Assert.True(ec.VerifyHash(hash, sig));

            hash[0] ^= 0xFF;
            Assert.False(ec.VerifyHash(hash, sig));
        });

    internal static void Assert_SignHash_NullHash_Throws(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
            Assert.Throws<ArgumentNullException>(() => ec.SignHash(null!)));

    internal static void Assert_VerifyHash_NullArguments_Throw(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
        {
            Assert.Throws<ArgumentNullException>(() => ec.VerifyHash(null!, new byte[64]));
            Assert.Throws<ArgumentNullException>(() => ec.VerifyHash(new byte[32], null!));
        });

    internal static void Assert_ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint(IPkcs11Backend backend, string curve)
    {
        var (_, _, expectedOidValue) = Spec(curve);
        WithEcDsa(backend, curve, (ec, _) =>
        {
            var p = ec.ExportParameters(includePrivateParameters: false);
            Assert.Equal(expectedOidValue, p.Curve.Oid.Value);
            Assert.NotNull(p.Q.X);
            Assert.NotNull(p.Q.Y);
            Assert.Null(p.D); // private parts must not be set
        });
    }

    // Cross-library verification: export the public key, rebuild an ECDsa from it, verify the PKCS#11
    // signature under the BCL — catches a wrong named-curve OID or mangled point. CKM_ECDSA emits raw
    // r‖s, so the BCL interprets the signature as IEEE P1363.
    internal static void Assert_SignData_VerifiesUnderBclFromExportedPublicKey(IPkcs11Backend backend, string curve) =>
        WithEcDsa(backend, curve, (ec, hash) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("cross-library verify");
            byte[] sig = ec.SignData(data, hash);

            using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));
            Assert.True(bcl.VerifyData(data, sig, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        });

    internal static void Assert_ExportParameters_Private_ThrowsInsecure(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
            Assert.Throws<InsecureOperationException>(() => ec.ExportParameters(includePrivateParameters: true)));

    internal static void Assert_ExportExplicitParameters_Throws(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
            Assert.Throws<NotSupportedException>(() => ec.ExportExplicitParameters(includePrivateParameters: false)));

    internal static void Assert_ImportParameters_Throws(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
            Assert.Throws<NotSupportedException>(() => ec.ImportParameters(default)));

    internal static void Assert_GenerateKey_Throws(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
            Assert.Throws<NotSupportedException>(() => ec.GenerateKey(BclECCurve.NamedCurves.nistP256)));
}
