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
/// (→ <c>AllowInsecure</c>). The real crypto is cross-checked against the BCL <see cref="MLKem"/> primitive
/// (FIPS 203). Crypto cases are gated on <see cref="MLKem.IsSupported"/>; argument/ctor cases that throw
/// before any native call stay <c>[Fact]</c>.
/// </summary>
public sealed class MLKemPkcs11Tests_Managed
{
    public static bool Supported => MLKem.IsSupported;

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
        workspace.AllowInsecure = allowInsecure;

        string label = $"mlkem-{Guid.NewGuid():N}";
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Label(label)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Label(label)
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

    public static TheoryData<CkpMlKem> ParameterSets =>
    [
        CkpMlKem.CKP_ML_KEM_512,
        CkpMlKem.CKP_ML_KEM_768,
        CkpMlKem.CKP_ML_KEM_1024,
    ];

    // === Encapsulate / decapsulate round-trips ============================

    [ConditionalTheory(nameof(Supported))]
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
    [ConditionalTheory(nameof(Supported))]
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
    [ConditionalFact(nameof(Supported))]
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

    [ConditionalFact(nameof(Supported))]
    public void Encapsulate_GatedByDefault_Throws() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: false, (ws, mlkem) =>
            Assert.Throws<InsecureOperationException>(() => mlkem.Encapsulate(out _, out _)));

    [ConditionalFact(nameof(Supported))]
    public void Decapsulate_GatedByDefault_Throws() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: false, (ws, mlkem) =>
        {
            // Produce a valid ciphertext off-token (no extraction needed) so the gate — not a bad
            // ciphertext — is what rejects the decapsulate.
            byte[] ek = mlkem.ExportEncapsulationKey();
            using var bcl = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, ek);
            bcl.Encapsulate(out byte[] ciphertext, out _);

            Assert.Throws<InsecureOperationException>(() => mlkem.Decapsulate(ciphertext));
        });

    // AllowInsecureScope() opts in only for its lifetime; outside it the gate re-engages.
    [ConditionalFact(nameof(Supported))]
    public void Encapsulate_AllowInsecureScope_OptsInThenReengages() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: false, (workspace, mlkem) =>
        {
            using (workspace.AllowInsecureScope())
                mlkem.Encapsulate(out _, out _); // must not throw inside the scope

            Assert.Throws<InsecureOperationException>(() => mlkem.Encapsulate(out _, out _));
        });

    // === Key material export ==============================================

    [ConditionalTheory(nameof(Supported))]
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

    [ConditionalFact(nameof(Supported))]
    public void ExportDecapsulationKey_ThrowsInsecure() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: true, (ws, mlkem) =>
            // Refused even with AllowInsecure: PKCS#11 keys are non-extractable by design.
            Assert.Throws<InsecureOperationException>(() => mlkem.ExportDecapsulationKey()));

    [ConditionalFact(nameof(Supported))]
    public void ExportPrivateSeed_ThrowsInsecure() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: true, (ws, mlkem) =>
            Assert.Throws<InsecureOperationException>(() => mlkem.ExportPrivateSeed()));

    [ConditionalFact(nameof(Supported))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: true, (ws, mlkem) =>
            Assert.Throws<InsecureOperationException>(() => mlkem.ExportPkcs8PrivateKey()));

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
