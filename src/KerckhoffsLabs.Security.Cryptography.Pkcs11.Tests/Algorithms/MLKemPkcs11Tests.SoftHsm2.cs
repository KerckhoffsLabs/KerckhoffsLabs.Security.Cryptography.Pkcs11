using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// MLKem (FIPS 203) export-to-PKCS#8 etc. are evaluation-only BCL APIs (SYSLIB5006); suppress here.
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

[Collection("SoftHsm")]
public sealed class MLKemPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;
    // The vendored SoftHSM is built WITH_ML_KEM when it detects OpenSSL 3.5+ (the CI Linux leg).
    // Tests needing a real ML-KEM key gate on this flag, so they run on an OpenSSL-3.5 build and
    // skip on a system-OpenSSL-3.0 build where CKM_ML_KEM_KEY_PAIR_GEN is unavailable.
    public static bool SoftHsmSupportsMlKem => SoftHsmBackendFixture.SoftHsmSupportsMlKem;

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

    // Generates an ML-KEM key pair for the given parameter set, wraps it, runs the body, then cleans up.
    private void WithMlKem(CkpMlKem parameterSet, Action<Pkcs11Workspace, MLKemPkcs11> body)
    {
        using var workspace = OpenWorkspace();
        string label = $"mlkem-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_DECAPSULATE, true).Build();

        var key = workspace.GenerateKey(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var mlkem = new MLKemPkcs11(key);
            body(workspace, mlkem);
        }
        finally
        {
            try { key.Delete(); }
            catch { /* best-effort cleanup */ }
            key.Dispose();
        }
    }

    // === Construction (executes — only needs a non-ML-KEM key) =============

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonMlKemKey_Throws()
    {
        using var workspace = OpenWorkspace();
        string label = $"mlkem-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new MLKemPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Encapsulate / decapsulate (needs a real ML-KEM backend) ==========

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlKem))]
    public void EncapsulateDecapsulate_RoundTrips() => WithMlKem(CkpMlKem.CKP_ML_KEM_768, (workspace, mlkem) =>
    {
        // Reading the shared secret is the extract-and-destroy path, gated by the secure-defaults policy.
        workspace.AllowInsecure = true;

        mlkem.Encapsulate(out byte[] ciphertext, out byte[] sharedSecretEnc);
        Assert.Equal(mlkem.Algorithm.CiphertextSizeInBytes, ciphertext.Length);
        Assert.Equal(mlkem.Algorithm.SharedSecretSizeInBytes, sharedSecretEnc.Length);

        byte[] sharedSecretDec = mlkem.Decapsulate(ciphertext);
        Assert.Equal(sharedSecretEnc, sharedSecretDec);
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlKem))]
    public void Encapsulate_GatedByDefault_Throws() => WithMlKem(CkpMlKem.CKP_ML_KEM_768, (ws, mlkem) =>
        // Without AllowInsecure, extracting the shared secret is refused.
        Assert.Throws<InsecureOperationException>(() => mlkem.Encapsulate(out _, out _)));

    // === Key material export ==============================================

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlKem))]
    public void ExportEncapsulationKey_ReturnsStandardEncoding() => WithMlKem(CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
    {
        byte[] ek = mlkem.ExportEncapsulationKey();
        Assert.Equal(mlkem.Algorithm.EncapsulationKeySizeInBytes, ek.Length);
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlKem))]
    public void ExportDecapsulationKey_ThrowsInsecure() => WithMlKem(CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
        Assert.Throws<InsecureOperationException>(() => mlkem.ExportDecapsulationKey()));

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlKem))]
    public void ExportPrivateSeed_ThrowsInsecure() => WithMlKem(CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
        Assert.Throws<InsecureOperationException>(() => mlkem.ExportPrivateSeed()));

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsMlKem))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() => WithMlKem(CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
        Assert.Throws<InsecureOperationException>(() => mlkem.ExportPkcs8PrivateKey()));
}
