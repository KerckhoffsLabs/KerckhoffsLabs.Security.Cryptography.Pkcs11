using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// SlhDsa (FIPS 205) and ExportPkcs8PrivateKey are evaluation-only BCL APIs (SYSLIB5006). We invoke
// them deliberately to assert our adapter's behaviour; suppress the experimental diagnostic here.
#pragma warning disable SYSLIB5006

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

[Collection("SoftHsm")]
public sealed class SlhDsaPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;
    // Upstream SoftHSM has no SLH-DSA (FIPS 205) support, so CKM_SLH_DSA_KEY_PAIR_GEN is unavailable.
    // Tests needing a real SLH-DSA key are gated on this flag and skip here, but are ready for an
    // SLH-DSA-capable backend (a future SoftHSM build that writes the marker, or a real HSM).
    public static bool SoftHsmSupportsSlhDsa => SoftHsmBackendFixture.SoftHsmSupportsSlhDsa;

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

    // Generates an SLH-DSA key pair for the given parameter set, wraps it as SlhDsaPkcs11, runs the
    // body, then destroys both handles. CKA_PARAMETER_SET goes on the public template.
    private void WithSlhDsa(CkpSlhDsa parameterSet, Action<SlhDsaPkcs11> body)
    {
        using var workspace = OpenWorkspace();
        string label = $"slhdsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_SLH_DSA)
            .Label(label).Id(id).Verify()
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_SLH_DSA)
            .Label(label).Id(id).Sign().Build();

        var key = workspace.GenerateKey(
            new Mechanism(CKM.CKM_SLH_DSA_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var slhdsa = new SlhDsaPkcs11(key);
            body(slhdsa);
        }
        finally
        {
            try { key.Delete(); }
            catch { /* best-effort cleanup */ }
            key.Dispose();
        }
    }

    // === Construction (executes — only needs a non-SLH-DSA key) ============

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonSlhDsaKey_Throws()
    {
        using var workspace = OpenWorkspace();
        string label = $"slhdsa-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new SlhDsaPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Sign / verify — pure SLH-DSA (needs a real SLH-DSA backend) =======

    [ConditionalTheory(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsSlhDsa))]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_128S)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHA2_192F)]
    [InlineData(CkpSlhDsa.CKP_SLH_DSA_SHAKE_256S)]
    public void SignVerifyData_RoundTrips(CkpSlhDsa parameterSet) => WithSlhDsa(parameterSet, slhdsa =>
    {
        byte[] data = Encoding.UTF8.GetBytes("slh-dsa round trip");
        byte[] sig = slhdsa.SignData(data);
        Assert.Equal(slhdsa.Algorithm.SignatureSizeInBytes, sig.Length);
        Assert.True(slhdsa.VerifyData(data, sig));

        byte[] tampered = [.. data];
        tampered[0] ^= 0xFF;
        Assert.False(slhdsa.VerifyData(tampered, sig));
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsSlhDsa))]
    public void SignVerifyData_WithContext_RoundTrips() => WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
    {
        byte[] data = Encoding.UTF8.GetBytes("context-bound message");
        byte[] context = Encoding.UTF8.GetBytes("app-context");

        byte[] sig = slhdsa.SignData(data, context);
        Assert.True(slhdsa.VerifyData(data, sig, context));
        // A signature made with a context must not verify without it.
        Assert.False(slhdsa.VerifyData(data, sig));
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsSlhDsa))]
    public void SignData_ContextTooLong_Throws() => WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
        // The BCL validates the >255-byte context first (ArgumentOutOfRangeException) before our own
        // ArgumentException would fire; both derive from ArgumentException.
        Assert.ThrowsAny<ArgumentException>(() => slhdsa.SignData(new byte[4], new byte[256])));

    // === HashSLH-DSA pre-hash — unsupported on PKCS#11 v3.2 ================
    //
    // SignPreHash / VerifyPreHash are intentionally not tested here: the BCL's pre-hash wrappers
    // validate / short-circuit before reaching our *Core overrides, so a test would assert BCL
    // behavior, not ours. The overrides still throw NotSupportedException by contract; they're simply
    // not reachable through the public surface to assert against.

    // === Key material export ===============================================

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsSlhDsa))]
    public void ExportSlhDsaPublicKey_ReturnsStandardEncoding() => WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
    {
        byte[] pub = slhdsa.ExportSlhDsaPublicKey();
        Assert.Equal(slhdsa.Algorithm.PublicKeySizeInBytes, pub.Length);
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsSlhDsa))]
    public void ExportSlhDsaPrivateKey_ThrowsInsecure() => WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
        Assert.Throws<InsecureOperationException>(() => slhdsa.ExportSlhDsaPrivateKey()));

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsSlhDsa))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => WithSlhDsa(CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
        Assert.Throws<InsecureOperationException>(() => slhdsa.ExportPkcs8PrivateKey()));
}
