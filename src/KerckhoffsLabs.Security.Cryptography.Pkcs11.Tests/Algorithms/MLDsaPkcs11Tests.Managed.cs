using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

#pragma warning disable SYSLIB5006 // ML-DSA (and its external-mu / PKCS#8 export members) are evaluation-only BCL APIs.

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// <see cref="MLDsaPkcs11"/> over the in-process <c>ManagedSoftToken</c>. SoftHSM is not built with
/// ML-DSA, so the SoftHsm KAT skips; here the managed token generates the key pair, signs, and verifies
/// entirely via the BCL <see cref="MLDsa"/> primitive (FIPS 204). This mirrors the SoftHsm behaviour set
/// (round-trips, context binding, context-length validation, external-mu refusal, key-material export
/// rules) and adds BCL cross-checks: the token's signature is verified with a BCL <c>MLDsa</c> rebuilt
/// from the exported public key. The crypto cases are gated on <see cref="MLDsa.IsSupported"/> (needs OS
/// PQC support — OpenSSL 3.5+ or a recent Windows); construction / argument-validation cases that throw
/// before any native call stay <c>[Fact]</c>.
/// </summary>
public sealed class MLDsaPkcs11Tests_Managed
{
    public static bool MlDsaSupported => MLDsa.IsSupported;

    private static MLDsaAlgorithm MapAlgorithm(CkpMlDsa parameterSet) => parameterSet switch
    {
        CkpMlDsa.CKP_ML_DSA_44 => MLDsaAlgorithm.MLDsa44,
        CkpMlDsa.CKP_ML_DSA_65 => MLDsaAlgorithm.MLDsa65,
        CkpMlDsa.CKP_ML_DSA_87 => MLDsaAlgorithm.MLDsa87,
        _ => throw new ArgumentOutOfRangeException(nameof(parameterSet)),
    };

    // Generates an ML-DSA key pair for the given parameter set on the managed token, wraps it as
    // MLDsaPkcs11, runs the body, then destroys the handle. CKA_PARAMETER_SET goes on the public template.
    private static void WithMlDsa(CkpMlDsa parameterSet, Action<MLDsaPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        string label = $"mldsa-{Guid.NewGuid():N}";
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA)
            .Label(label).Verify()
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA)
            .Label(label).Sign().Build();

        var key = workspace.GenerateKey(
            new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var mldsa = new MLDsaPkcs11(key);
            body(mldsa);
        }
        finally
        {
            try { key.Destroy(); }
            catch { /* best-effort cleanup */ }
            key.Dispose();
        }
    }

    // === Sign / verify — pure ML-DSA, cross-checked against the BCL ========

    [ConditionalTheory(nameof(MlDsaSupported))]
    [InlineData(CkpMlDsa.CKP_ML_DSA_44)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_65)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_87)]
    public void SignVerifyData_RoundTrips(CkpMlDsa parameterSet) => WithMlDsa(parameterSet, mldsa =>
    {
        Assert.Equal(MapAlgorithm(parameterSet), mldsa.Algorithm);

        byte[] data = Encoding.UTF8.GetBytes("ml-dsa round trip");
        byte[] sig = mldsa.SignData(data);
        Assert.Equal(mldsa.Algorithm.SignatureSizeInBytes, sig.Length);
        Assert.True(mldsa.VerifyData(data, sig));

        byte[] tamperedMessage = [.. data];
        tamperedMessage[0] ^= 0xFF;
        Assert.False(mldsa.VerifyData(tamperedMessage, sig));

        byte[] tamperedSig = [.. sig];
        tamperedSig[0] ^= 0xFF;
        Assert.False(mldsa.VerifyData(data, tamperedSig));
    });

    // The token's signature must verify under a BCL MLDsa rebuilt from the exported public key.
    [ConditionalTheory(nameof(MlDsaSupported))]
    [InlineData(CkpMlDsa.CKP_ML_DSA_44)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_65)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_87)]
    public void SignData_VerifiesWithBcl(CkpMlDsa parameterSet) => WithMlDsa(parameterSet, mldsa =>
    {
        byte[] data = Encoding.UTF8.GetBytes("token-signed, bcl-verified");
        byte[] sig = mldsa.SignData(data);

        byte[] pub = mldsa.ExportMLDsaPublicKey();
        using var bcl = MLDsa.ImportMLDsaPublicKey(MapAlgorithm(parameterSet), pub);
        Assert.True(bcl.VerifyData(data, sig));

        byte[] tampered = [.. data];
        tampered[0] ^= 0xFF;
        Assert.False(bcl.VerifyData(tampered, sig));
    });

    [ConditionalFact(nameof(MlDsaSupported))]
    public void SignVerifyData_WithContext_RoundTrips() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
    {
        byte[] data = Encoding.UTF8.GetBytes("context-bound message");
        byte[] context = Encoding.UTF8.GetBytes("app-context");

        byte[] sig = mldsa.SignData(data, context);
        Assert.True(mldsa.VerifyData(data, sig, context));
        // A signature made with a context must not verify without it.
        Assert.False(mldsa.VerifyData(data, sig));
        // ...nor under a different context.
        Assert.False(mldsa.VerifyData(data, sig, Encoding.UTF8.GetBytes("other-context")));

        // Cross-check: the BCL (rebuilt from the exported public key) agrees on context binding.
        byte[] pub = mldsa.ExportMLDsaPublicKey();
        using var bcl = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, pub);
        Assert.True(bcl.VerifyData(data, sig, context));
        Assert.False(bcl.VerifyData(data, sig));
    });

    [ConditionalFact(nameof(MlDsaSupported))]
    public void SignData_ContextTooLong_Throws() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        // The BCL validates the >255-byte context first (ArgumentOutOfRangeException) before our own
        // ArgumentException would fire; both derive from ArgumentException.
        Assert.ThrowsAny<ArgumentException>(() => mldsa.SignData(new byte[4], new byte[256])));

    // === External-mu / pre-hash — unsupported on PKCS#11 v3.2 =============
    //
    // HashML-DSA pre-hash (SignPreHash/VerifyPreHash) is intentionally not tested: the BCL's
    // evaluation-only pre-hash wrappers validate/short-circuit before reaching our *Core overrides, so a
    // test would assert BCL behaviour, not ours. External-mu reaches our overrides and is asserted here.

    [ConditionalFact(nameof(MlDsaSupported))]
    public void SignMu_Throws() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        Assert.Throws<NotSupportedException>(() => mldsa.SignMu(new byte[64])));

    [ConditionalFact(nameof(MlDsaSupported))]
    public void VerifyMu_Throws() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        Assert.Throws<NotSupportedException>(() =>
            mldsa.VerifyMu(new byte[64], new byte[mldsa.Algorithm.SignatureSizeInBytes])));

    // === Key-material export ==============================================

    [ConditionalTheory(nameof(MlDsaSupported))]
    [InlineData(CkpMlDsa.CKP_ML_DSA_44)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_65)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_87)]
    public void ExportMLDsaPublicKey_ReturnsStandardEncoding(CkpMlDsa parameterSet) =>
        WithMlDsa(parameterSet, mldsa =>
        {
            byte[] pub = mldsa.ExportMLDsaPublicKey();
            Assert.Equal(mldsa.Algorithm.PublicKeySizeInBytes, pub.Length);
            // It is a valid FIPS 204 public-key encoding (the BCL accepts it).
            using var bcl = MLDsa.ImportMLDsaPublicKey(MapAlgorithm(parameterSet), pub);
            Assert.Equal(MapAlgorithm(parameterSet), bcl.Algorithm);
        });

    [ConditionalFact(nameof(MlDsaSupported))]
    public void ExportMLDsaPrivateKey_ThrowsInsecure() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        Assert.Throws<InsecureOperationException>(() => mldsa.ExportMLDsaPrivateKey()));

    [ConditionalFact(nameof(MlDsaSupported))]
    public void ExportMLDsaPrivateSeed_ThrowsInsecure() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        Assert.Throws<InsecureOperationException>(() => mldsa.ExportMLDsaPrivateSeed()));

    [ConditionalFact(nameof(MlDsaSupported))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        Assert.Throws<InsecureOperationException>(() => mldsa.ExportPkcs8PrivateKey()));

    // === Construction / argument validation (run before any native call) ==

    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new MLDsaPkcs11(null!));

    [Fact]
    public void Ctor_NonMlDsaKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("aes").ValueLen(32).Encrypt().Decrypt().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new MLDsaPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }
}
