using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// MLKem (FIPS 203) is an evaluation-only BCL API (SYSLIB5006); suppress here.
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// MLKemPkcs11 over the in-process <c>ManagedSoftToken</c> (a BCL-backed PKCS#11 fake). The vendored
/// SoftHSM is not built WITH_ML_KEM, so the SoftHsm KAT skips; the managed token generates the key pair
/// and runs <c>C_EncapsulateKey</c>/<c>C_DecapsulateKey</c>, with both sides recovering the same shared
/// secret. Reading the shared secret is the extract-and-destroy path, gated by the secure-defaults policy
/// (via <c>UsePolicy(CryptoPolicy.AllowInsecure)</c>). The real crypto is cross-checked against the BCL
/// <see cref="MLKem"/> primitive
/// (FIPS 203). Crypto cases are gated on <see cref="MLKem.IsSupported"/>; argument/ctor cases that throw
/// before any native call stay <c>[Fact]</c>.
/// </summary>
[NoBackendCollection("Drives a per-test ManagedSoftToken in process — no native module is loaded and " +
                     "the token holds no static state, so this is safe alongside every backend collection.")]
public sealed class MLKemPkcs11Tests_Managed
{
    private static MLKemAlgorithm BclAlgorithm(CkpMlKem p) => p switch
    {
        CkpMlKem.CKP_ML_KEM_512 => MLKemAlgorithm.MLKem512,
        CkpMlKem.CKP_ML_KEM_768 => MLKemAlgorithm.MLKem768,
        CkpMlKem.CKP_ML_KEM_1024 => MLKemAlgorithm.MLKem1024,
        _ => throw new ArgumentOutOfRangeException(nameof(p)),
    };

    // Generates an ML-KEM key pair for the given parameter set on the managed token, wraps it as an
    // MLKemPkcs11, runs the body, then cleans up the key.
    private static void WithMlKem(CkpMlKem parameterSet, bool allowInsecure, Action<Pkcs11Workspace, MLKemPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using IDisposable? insecure = allowInsecure ? workspace.UsePolicy(CryptoPolicy.AllowInsecure) : null;

        string label = $"mlkem-{Guid.NewGuid():N}";
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Label(label)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Label(label)
            .Attribute(CKA.CKA_DECAPSULATE, true).Build();

        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var mlkem = new MLKemPkcs11(key);
            body(workspace, mlkem);
        }
        finally
        {
            try { key.Destroy(); }
            catch { /* best-effort cleanup */ }
        }
    }

    // CA1825 false-positives on the xUnit TheoryData collection expression (it is not a zero-length
    // array); the collection expression is the form IDE0028 and the repo .editorconfig prefer.
#pragma warning disable CA1825
    public static TheoryData<CkpMlKem> ParameterSets =>
    [
        CkpMlKem.CKP_ML_KEM_512,
        CkpMlKem.CKP_ML_KEM_768,
        CkpMlKem.CKP_ML_KEM_1024,
    ];
#pragma warning restore CA1825

    // === Encapsulate / decapsulate round-trips ============================

    [Theory(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    [MemberData(nameof(ParameterSets))]
    public void EncapsulateDecapsulate_RoundTrips(CkpMlKem parameterSet) =>
        WithMlKem(parameterSet, allowInsecure: true, (ws, mlkem) =>
    {
        Assert.Equal(BclAlgorithm(parameterSet), mlkem.Algorithm);

        mlkem.Encapsulate(out byte[] ciphertext, out byte[] sharedSecretEnc);
        Assert.Equal(mlkem.Algorithm.CiphertextSizeInBytes, ciphertext.Length);
        Assert.Equal(mlkem.Algorithm.SharedSecretSizeInBytes, sharedSecretEnc.Length);

        byte[] sharedSecretDec = mlkem.Decapsulate(ciphertext);
        Assert.Equal(sharedSecretEnc, sharedSecretDec);
    });

    // BCL cross-check: export the encapsulation key from the token, import it into a BCL MLKem,
    // encapsulate off-token, then decapsulate the resulting ciphertext on the token. The shared secrets
    // must match — the token holds the matching decapsulation key.
    [Theory(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    [MemberData(nameof(ParameterSets))]
    public void Decapsulate_BclEncapsulation_MatchesSharedSecret(CkpMlKem parameterSet) =>
        WithMlKem(parameterSet, allowInsecure: true, (ws, mlkem) =>
    {
        byte[] ek = mlkem.ExportEncapsulationKey();

        using var bcl = MLKem.ImportEncapsulationKey(BclAlgorithm(parameterSet), ek);
        bcl.Encapsulate(out byte[] ciphertext, out byte[] bclSharedSecret);

        byte[] tokenSharedSecret = mlkem.Decapsulate(ciphertext);
        Assert.Equal(bclSharedSecret, tokenSharedSecret);
    });

    // Two encapsulations to the same key produce distinct ciphertexts and distinct shared secrets,
    // yet each round-trips correctly.
    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Encapsulate_TwiceProducesDistinctCiphertexts() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: true, (ws, mlkem) =>
    {
        mlkem.Encapsulate(out byte[] ct1, out byte[] ss1);
        mlkem.Encapsulate(out byte[] ct2, out byte[] ss2);

        Assert.NotEqual(ct1, ct2);
        Assert.NotEqual(ss1, ss2);
        Assert.Equal(ss1, mlkem.Decapsulate(ct1));
        Assert.Equal(ss2, mlkem.Decapsulate(ct2));
    });

    // === Secure-defaults gating ===========================================

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Encapsulate_GatedByDefault_Throws() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: false, (ws, mlkem) =>
            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.Encapsulate(out _, out _)));

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Decapsulate_GatedByDefault_Throws() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: false, (ws, mlkem) =>
        {
            // Produce a valid ciphertext off-token (no extraction needed) so the gate — not a bad
            // ciphertext — is what rejects the decapsulate.
            byte[] ek = mlkem.ExportEncapsulationKey();
            using var bcl = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, ek);
            bcl.Encapsulate(out byte[] ciphertext, out _);

            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.Decapsulate(ciphertext));
        });

    // UsePolicy(CryptoPolicy.AllowInsecure) opts in only for its lifetime; outside it the gate re-engages.
    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Encapsulate_UsePolicyAllowInsecure_OptsInThenReengages() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: false, (workspace, mlkem) =>
        {
            using (workspace.UsePolicy(CryptoPolicy.AllowInsecure))
                mlkem.Encapsulate(out _, out _); // must not throw inside the scope

            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.Encapsulate(out _, out _));
        });

    // === Extract-and-destroy cleanup failures =============================

    // The extract-and-destroy path creates a transient, extractable shared-secret object on the
    // token, reads its bytes, then destroys it. If C_DestroyObject fails, that extractable copy
    // lingers on-token — the adapter must surface the failure (not swallow it) and must not hand
    // back a shared secret alongside a failed cleanup.
    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Encapsulate_WhenDestroyFails_SurfacesPkcs11Exception()
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure);

        string label = $"mlkem-{Guid.NewGuid():N}";
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Label(label)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlKem.CKP_ML_KEM_768).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Label(label)
            .Attribute(CKA.CKA_DECAPSULATE, true).Build();

        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var mlkem = new MLKemPkcs11(key);

            // Make every C_DestroyObject report failure so the shared-secret object cannot be removed.
            token.DestroyObjectResultOverride = CKR.CKR_FUNCTION_FAILED;

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => mlkem.Encapsulate(out _, out _));
            Assert.Equal(CKR.CKR_FUNCTION_FAILED, ex.ReturnValue);
        }
        finally
        {
            // Lift the override so the key can actually be cleaned up.
            token.DestroyObjectResultOverride = null;
            try { key.Destroy(); }
            catch { /* best-effort cleanup */ }
        }
    }

    // === Key material export ==============================================

    [Theory(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    [MemberData(nameof(ParameterSets))]
    public void ExportEncapsulationKey_MatchesBclEncodingLength(CkpMlKem parameterSet) =>
        WithMlKem(parameterSet, allowInsecure: false, (ws, mlkem) =>
    {
        byte[] ek = mlkem.ExportEncapsulationKey();
        Assert.Equal(mlkem.Algorithm.EncapsulationKeySizeInBytes, ek.Length);

        // The exported bytes are the FIPS 203 encapsulation-key encoding: importable by the BCL.
        using var bcl = MLKem.ImportEncapsulationKey(BclAlgorithm(parameterSet), ek);
        Assert.Equal(BclAlgorithm(parameterSet), bcl.Algorithm);
    });

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void ExportDecapsulationKey_ThrowsInsecure() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: true, (ws, mlkem) =>
            // Refused even under the AllowInsecure policy: PKCS#11 keys are non-extractable by design.
            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.ExportDecapsulationKey()));

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void ExportPrivateSeed_ThrowsInsecure() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: true, (ws, mlkem) =>
            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.ExportPrivateSeed()));

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: true, (ws, mlkem) =>
            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.ExportPkcs8PrivateKey()));

    // === Construction and argument validation (run before any native crypto) ==============

    [Fact]
    public void Ctor_NullKey_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new MLKemPkcs11(null!));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public void Ctor_NonMlKemKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("aes").ValueLen(32).Encrypt().Decrypt().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new MLKemPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }
}
