using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// External-mu (SignMu/VerifyMu) and ExportPkcs8PrivateKey are evaluation-only BCL APIs
// (SYSLIB5006). We invoke them deliberately to assert our adapter's behaviour; suppress the
// experimental diagnostic for this file.
#pragma warning disable SYSLIB5006

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

[Collection("SoftHsm")]
public sealed class MLDsaPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;
    // The vendored SoftHSM binary is not compiled WITH_ML_DSA, so CKM_ML_DSA_KEY_PAIR_GEN returns
    // CKR_MECHANISM_INVALID. Tests needing a real ML-DSA key are gated on this flag and skip here,
    // but are ready for an ML-DSA-capable backend (a SoftHSM built with ML-DSA, or a real HSM).
    public static bool SoftHsmSupportsMlDsa => SoftHsmBackendFixture.SoftHsmSupportsMlDsa;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    // Generates an ML-DSA key pair for the given parameter set, wraps it as MLDsaPkcs11, runs the
    // body, then destroys both handles. CKA_PARAMETER_SET goes on the public template.
    private void WithMlDsa(CkpMlDsa parameterSet, Action<MLDsaPkcs11> body)
    {
        using var workspace = OpenWorkspace();
        string label = $"mldsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA)
            .Label(label).Id(id).Verify()
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA)
            .Label(label).Id(id).Sign().Build();

        var key = workspace.GenerateKey(
            new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var mldsa = new MLDsaPkcs11(key);
            body(mldsa);
        }
        finally
        {
            try { key.Delete(); }
            catch { /* best-effort cleanup */ }
            key.Dispose();
        }
    }

    // === Construction (executes — only needs a non-ML-DSA key) =============

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonMlDsaKey_Throws()
    {
        using var workspace = OpenWorkspace();
        string label = $"mldsa-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
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

    // === Sign / verify — pure ML-DSA (needs a real ML-DSA backend) =========

    [ConditionalTheory(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlDsa))]
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

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlDsa))]
    public void SignVerifyData_WithContext_RoundTrips() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
    {
        byte[] data = Encoding.UTF8.GetBytes("context-bound message");
        byte[] context = Encoding.UTF8.GetBytes("app-context");

        byte[] sig = mldsa.SignData(data, context);
        Assert.True(mldsa.VerifyData(data, sig, context));
        // A signature made with a context must not verify without it.
        Assert.False(mldsa.VerifyData(data, sig));
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlDsa))]
    public void SignData_ContextTooLong_Throws() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        // The BCL validates the >255-byte context first (ArgumentOutOfRangeException) before our
        // own ArgumentException would fire; both derive from ArgumentException.
        Assert.ThrowsAny<ArgumentException>(() => mldsa.SignData(new byte[4], new byte[256])));

    // === External-mu — unsupported on PKCS#11 v3.2 =========================
    //
    // HashML-DSA pre-hash (SignPreHash/VerifyPreHash) is intentionally not tested here: the BCL's
    // evaluation-only pre-hash wrappers validate/short-circuit before reaching our *Core overrides
    // (SignPreHash surfaces CryptographicException, VerifyPreHash returns false without throwing),
    // so a test would assert BCL behavior, not ours. The overrides still throw NotSupportedException
    // by contract; they're simply not reachable through the public surface to assert against.

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlDsa))]
    public void SignMu_Throws() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        Assert.Throws<NotSupportedException>(() => mldsa.SignMu(new byte[64])));

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlDsa))]
    public void VerifyMu_Throws() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        Assert.Throws<NotSupportedException>(() =>
            mldsa.VerifyMu(new byte[64], new byte[mldsa.Algorithm.SignatureSizeInBytes])));

    // === Key material export ===============================================

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlDsa))]
    public void ExportMLDsaPublicKey_ReturnsStandardEncoding() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
    {
        byte[] pub = mldsa.ExportMLDsaPublicKey();
        Assert.Equal(mldsa.Algorithm.PublicKeySizeInBytes, pub.Length);
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlDsa))]
    public void ExportMLDsaPrivateKey_ThrowsInsecure() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        Assert.Throws<InsecureOperationException>(() => mldsa.ExportMLDsaPrivateKey()));

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlDsa))]
    public void ExportMLDsaPrivateSeed_ThrowsInsecure() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        Assert.Throws<InsecureOperationException>(() => mldsa.ExportMLDsaPrivateSeed()));

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlDsa))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => WithMlDsa(CkpMlDsa.CKP_ML_DSA_65, mldsa =>
        Assert.Throws<InsecureOperationException>(() => mldsa.ExportPkcs8PrivateKey()));
}
