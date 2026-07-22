using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

// External-mu (SignMu/VerifyMu) and ExportPkcs8PrivateKey are evaluation-only BCL APIs (SYSLIB5006).
// We invoke them deliberately to assert our adapter's behaviour; suppress the experimental diagnostic.
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic MLDsaPkcs11 (FIPS 204) tests: sign/verify across parameter sets and with context,
/// independent BCL cross-verification of token signatures, external-mu (unsupported on PKCS#11 v3.2),
/// and key-material export (public encoding; private export refused). The non-ML-DSA-key constructor
/// check runs anywhere; the real-crypto cases skip where the backend cannot operate ML-DSA
/// (<see cref="IPkcs11Backend.SupportsMlDsa"/>).
/// </summary>
internal static class MLDsaPkcs11TestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    // Generates an ML-DSA key pair for the parameter set, wraps it as MLDsaPkcs11, runs the body, then
    // destroys both handles. Skips where the backend cannot operate ML-DSA. CKA_PARAMETER_SET goes on
    // the public template.
    private static void WithMlDsa(IPkcs11Backend backend, CkpMlDsa parameterSet, Action<MLDsaPkcs11> body)
    {
        if (!backend.SupportsMlDsa)
            throw new SkipTestException("Backend cannot operate ML-DSA (CKM_ML_DSA unavailable).");

        using var workspace = OpenWorkspace(backend);
        string label = $"mldsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA)
            .Label(label).Id(id).Verify()
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA)
            .Label(label).Id(id).Sign().Build();

        var key = workspace.GenerateKey(new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var mldsa = new MLDsaPkcs11(key);
            body(mldsa);
        }
        finally
        {
            try { key.Delete(); } catch { /* best-effort cleanup */ }
            key.Dispose();
        }
    }

    internal static void Assert_Ctor_NonMlDsaKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"mldsa-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new MLDsaPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_SignVerifyData_RoundTrips(IPkcs11Backend backend, CkpMlDsa parameterSet) =>
        WithMlDsa(backend, parameterSet, mldsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("ml-dsa round trip");
            byte[] sig = mldsa.SignData(data);
            Assert.Equal(mldsa.Algorithm.SignatureSizeInBytes, sig.Length);
            Assert.True(mldsa.VerifyData(data, sig));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(mldsa.VerifyData(tampered, sig));
        });

    private static MLDsaAlgorithm BclAlgorithm(CkpMlDsa parameterSet) => parameterSet switch
    {
        CkpMlDsa.CKP_ML_DSA_44 => MLDsaAlgorithm.MLDsa44,
        CkpMlDsa.CKP_ML_DSA_65 => MLDsaAlgorithm.MLDsa65,
        CkpMlDsa.CKP_ML_DSA_87 => MLDsaAlgorithm.MLDsa87,
        _ => throw new ArgumentOutOfRangeException(nameof(parameterSet)),
    };

    // Independent verification: the token's signature must verify under a BCL MLDsa rebuilt from the
    // exported public key. A round-trip alone cannot catch a mechanism-params mis-encoding (context,
    // parameter set) that the token's own sign and verify paths share; a second implementation can.
    internal static void Assert_SignData_VerifiesWithBcl(IPkcs11Backend backend, CkpMlDsa parameterSet)
    {
        if (!MLDsa.IsSupported)
            throw new SkipTestException("Host BCL cannot operate ML-DSA (needs OpenSSL 3.5+ or a recent Windows).");

        WithMlDsa(backend, parameterSet, mldsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("token-signed, bcl-verified");
            byte[] context = Encoding.UTF8.GetBytes("app-context");
            byte[] sig = mldsa.SignData(data);
            byte[] contextSig = mldsa.SignData(data, context);

            byte[] pub = mldsa.ExportMLDsaPublicKey();
            using var bcl = MLDsa.ImportMLDsaPublicKey(BclAlgorithm(parameterSet), pub);

            Assert.True(bcl.VerifyData(data, sig));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(bcl.VerifyData(tampered, sig));

            // The BCL agrees on context binding: valid with the context, invalid without.
            Assert.True(bcl.VerifyData(data, contextSig, context));
            Assert.False(bcl.VerifyData(data, contextSig));
        });
    }

    internal static void Assert_SignVerifyData_WithContext_RoundTrips(IPkcs11Backend backend) =>
        WithMlDsa(backend, CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("context-bound message");
            byte[] context = Encoding.UTF8.GetBytes("app-context");

            byte[] sig = mldsa.SignData(data, context);
            Assert.True(mldsa.VerifyData(data, sig, context));
            // A signature made with a context must not verify without it.
            Assert.False(mldsa.VerifyData(data, sig));
        });

    internal static void Assert_SignData_ContextTooLong_Throws(IPkcs11Backend backend) =>
        WithMlDsa(backend, CkpMlDsa.CKP_ML_DSA_65, mldsa =>
            // The BCL validates the >255-byte context first (ArgumentOutOfRangeException) before our own
            // ArgumentException would fire; both derive from ArgumentException.
            Assert.ThrowsAny<ArgumentException>(() => mldsa.SignData(new byte[4], new byte[256])));

    internal static void Assert_SignMu_Throws(IPkcs11Backend backend) =>
        WithMlDsa(backend, CkpMlDsa.CKP_ML_DSA_65, mldsa =>
            Assert.Throws<NotSupportedException>(() => mldsa.SignMu(new byte[64])));

    internal static void Assert_VerifyMu_Throws(IPkcs11Backend backend) =>
        WithMlDsa(backend, CkpMlDsa.CKP_ML_DSA_65, mldsa =>
            Assert.Throws<NotSupportedException>(() =>
                mldsa.VerifyMu(new byte[64], new byte[mldsa.Algorithm.SignatureSizeInBytes])));

    internal static void Assert_ExportMLDsaPublicKey_ReturnsStandardEncoding(IPkcs11Backend backend) =>
        WithMlDsa(backend, CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        {
            byte[] pub = mldsa.ExportMLDsaPublicKey();
            Assert.Equal(mldsa.Algorithm.PublicKeySizeInBytes, pub.Length);
        });

    internal static void Assert_ExportMLDsaPrivateKey_ThrowsInsecure(IPkcs11Backend backend) =>
        WithMlDsa(backend, CkpMlDsa.CKP_ML_DSA_65, mldsa =>
            Assert.Throws<InsecureOperationException>(() => mldsa.ExportMLDsaPrivateKey()));

    internal static void Assert_ExportMLDsaPrivateSeed_ThrowsInsecure(IPkcs11Backend backend) =>
        WithMlDsa(backend, CkpMlDsa.CKP_ML_DSA_65, mldsa =>
            Assert.Throws<InsecureOperationException>(() => mldsa.ExportMLDsaPrivateSeed()));

    internal static void Assert_ExportPkcs8PrivateKey_ThrowsInsecure(IPkcs11Backend backend) =>
        WithMlDsa(backend, CkpMlDsa.CKP_ML_DSA_65, mldsa =>
            Assert.Throws<InsecureOperationException>(() => mldsa.ExportPkcs8PrivateKey()));
}
