using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// ML-DSA (FIPS 204) against the second real backend (opencryptoki). opencryptoki's software token
/// advertises <c>CKM_ML_DSA</c> only when the loaded OpenSSL is ≥ 3.5 (it probes the OID at token
/// init); the CI job puts OpenSSL 3.5 on the test host's loader path, so these run there and skip
/// elsewhere. Each ML-DSA test gates on the live mechanism list via <see cref="SkipTestException"/>.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class MLDsaPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    // Generates an ML-DSA key pair for the given parameter set, wraps it, runs the body, cleans up.
    private void WithMlDsa(CkpMlDsa parameterSet, Action<MLDsaPkcs11> body)
    {
        if (!_backend.Supports(CKM.CKM_ML_DSA))
            throw new SkipTestException("opencryptoki: CKM_ML_DSA not available (needs OpenSSL >= 3.5).");

        using var workspace = OpenWorkspace();
        string label = $"octk-mldsa-{Guid.NewGuid():N}";
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
            try { key.Delete(); } catch { /* best-effort */ }
            key.Dispose();
        }
    }

    [ConditionalTheory(nameof(Available))]
    [InlineData(CkpMlDsa.CKP_ML_DSA_44)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_65)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_87)]
    public void SignVerifyData_RoundTrips(CkpMlDsa parameterSet) => WithMlDsa(parameterSet, mldsa =>
    {
        byte[] data = Encoding.UTF8.GetBytes("ml-dsa round trip");
        byte[] sig = mldsa.SignData(data);
        Assert.Equal(mldsa.Algorithm.SignatureSizeInBytes, sig.Length);
        Assert.True(mldsa.VerifyData(data, sig));

        byte[] tampered = [.. data];
        tampered[0] ^= 0xFF;
        Assert.False(mldsa.VerifyData(tampered, sig));
    });

    [ConditionalFact(nameof(Available))]
    public void SignVerifyData_WithContext_RoundTrips() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
    {
        byte[] data = Encoding.UTF8.GetBytes("context-bound message");
        byte[] context = Encoding.UTF8.GetBytes("app-context");

        byte[] sig = mldsa.SignData(data, context);
        Assert.True(mldsa.VerifyData(data, sig, context));
        Assert.False(mldsa.VerifyData(data, sig)); // a context-bound signature must not verify without it
    });

    [ConditionalFact(nameof(Available))]
    public void ExportMLDsaPublicKey_ReturnsStandardEncoding() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
    {
        byte[] pub = mldsa.ExportMLDsaPublicKey();
        Assert.Equal(mldsa.Algorithm.PublicKeySizeInBytes, pub.Length);
    });

    [ConditionalFact(nameof(Available))]
    public void ExportMLDsaPrivateKey_ThrowsInsecure() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        Assert.Throws<InsecureOperationException>(() => mldsa.ExportMLDsaPrivateKey()));
}
