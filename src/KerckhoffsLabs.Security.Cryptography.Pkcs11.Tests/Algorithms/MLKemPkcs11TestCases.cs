using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// MLKem (FIPS 203) export-to-PKCS#8 etc. are evaluation-only BCL APIs (SYSLIB5006); suppress here.
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic MLKemPkcs11 (FIPS 203) tests: encapsulate/decapsulate round-trip (extracting the
/// shared secret is gated by the secure-defaults policy), independent BCL cross-encapsulation against
/// the token's decapsulation, and key-material export (encapsulation key encoding; private export
/// refused). The non-ML-KEM-key constructor check runs anywhere; the real-crypto cases skip where the
/// backend cannot operate ML-KEM (<see cref="IPkcs11Backend.SupportsMlKem"/>).
/// </summary>
internal static class MLKemPkcs11TestCases
{
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

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    // Generates an ML-KEM key pair for the parameter set, wraps it, runs the body, then cleans up.
    // Skips where the backend cannot operate ML-KEM, or where its CKM_ML_KEM_KEY_PAIR_GEN key-size
    // range does not cover this specific parameter set (e.g. NSS only added ML-KEM-512 in 3.129).
    private static void WithMlKem(IPkcs11Backend backend, CkpMlKem parameterSet, Action<Pkcs11Workspace, MLKemPkcs11> body)
    {
        backend.RequireMlKemParameterSet(BclAlgorithm(parameterSet).EncapsulationKeySizeInBytes);

        using var workspace = OpenWorkspace(backend);
        string label = $"mlkem-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_DECAPSULATE, true).Build();

        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var mlkem = new MLKemPkcs11(key);
            body(workspace, mlkem);
        }
        finally
        {
            try { key.Destroy(); } catch { /* best-effort cleanup */ }
        }
    }

    internal static void Assert_Ctor_NonMlKemKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"mlkem-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build())
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

    internal static void Assert_EncapsulateDecapsulate_RoundTrips(IPkcs11Backend backend, CkpMlKem parameterSet) =>
        WithMlKem(backend, parameterSet, (workspace, mlkem) =>
        {
            // Reading the shared secret is the extract-and-destroy path, gated by the secure-defaults policy.
            using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure);

            mlkem.Encapsulate(out byte[] ciphertext, out byte[] sharedSecretEnc);
            Assert.Equal(mlkem.Algorithm.CiphertextSizeInBytes, ciphertext.Length);
            Assert.Equal(mlkem.Algorithm.SharedSecretSizeInBytes, sharedSecretEnc.Length);

            byte[] sharedSecretDec = mlkem.Decapsulate(ciphertext);
            Assert.Equal(sharedSecretEnc, sharedSecretDec);
        });

    private static MLKemAlgorithm BclAlgorithm(CkpMlKem parameterSet) => parameterSet switch
    {
        CkpMlKem.CKP_ML_KEM_512 => MLKemAlgorithm.MLKem512,
        CkpMlKem.CKP_ML_KEM_768 => MLKemAlgorithm.MLKem768,
        CkpMlKem.CKP_ML_KEM_1024 => MLKemAlgorithm.MLKem1024,
        _ => throw new ArgumentOutOfRangeException(nameof(parameterSet)),
    };

    // Independent verification: encapsulate off-token with a BCL MLKem built from the exported
    // encapsulation key, then decapsulate on the token — the shared secrets must match. A round-trip
    // alone cannot catch a mis-encoding that the token's own encapsulate and decapsulate share; a
    // second implementation can.
    internal static void Assert_Decapsulate_BclEncapsulation_MatchesSharedSecret(IPkcs11Backend backend, CkpMlKem parameterSet)
    {
        if (!MLKem.IsSupported)
            Assert.Skip("Host BCL cannot operate ML-KEM (needs OpenSSL 3.5+ or a recent Windows).");

        WithMlKem(backend, parameterSet, (workspace, mlkem) =>
        {
            // Reading the token's decapsulated secret is the extract-and-destroy path, gated by the
            // secure-defaults policy.
            using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure);

            byte[] ek = mlkem.ExportEncapsulationKey();
            using var bcl = MLKem.ImportEncapsulationKey(BclAlgorithm(parameterSet), ek);
            bcl.Encapsulate(out byte[] ciphertext, out byte[] bclSharedSecret);

            byte[] tokenSharedSecret = mlkem.Decapsulate(ciphertext);
            Assert.Equal(bclSharedSecret, tokenSharedSecret);
        });
    }

    internal static void Assert_Encapsulate_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithMlKem(backend, CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
            // Without the AllowInsecure policy, extracting the shared secret is refused.
            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.Encapsulate(out byte[] _, out byte[] _)));

    internal static void Assert_ExportEncapsulationKey_ReturnsStandardEncoding(IPkcs11Backend backend, CkpMlKem parameterSet) =>
        WithMlKem(backend, parameterSet, (_, mlkem) =>
        {
            byte[] ek = mlkem.ExportEncapsulationKey();
            Assert.Equal(mlkem.Algorithm.EncapsulationKeySizeInBytes, ek.Length);
        });

    internal static void Assert_ExportDecapsulationKey_ThrowsInsecure(IPkcs11Backend backend) =>
        WithMlKem(backend, CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.ExportDecapsulationKey()));

    internal static void Assert_ExportPrivateSeed_ThrowsInsecure(IPkcs11Backend backend) =>
        WithMlKem(backend, CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.ExportPrivateSeed()));

    internal static void Assert_ExportPkcs8PrivateKey_ThrowsInsecure(IPkcs11Backend backend) =>
        WithMlKem(backend, CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.ExportPkcs8PrivateKey()));

    // Regression guard for MLKemPkcs11's per-library CKA_VALUE_LEN quirk cache
    // (Pkcs11Library.MlKemDecapsulateOmitsValueLen): every other case above decapsulates at most once
    // per key/workspace, so none of them exercises the *cached* branch of DecapsulateCore's switch
    // (`bool omit => DecapsulateWith(...)`) at all -- only DecapsulateProbing's first-call path. A bug
    // that swapped the two outcomes in DecapsulateProbing (recording `true` where SoftHSM's rejection
    // should record `false`, or vice versa) would still pass every round-trip test above, because the
    // first call always tries the same order regardless of what gets cached; only a second call reading
    // the wrong cached value back would fail, and would fail loudly with a token-level error rather than
    // a wrong shared secret. Decapsulating twice against the same key forces both branches and pins the
    // exact per-backend value, per the divergence documented on MlKemDecapsulateOmitsValueLen itself.
    internal static void Assert_Decapsulate_CachesValueLenQuirkPerLibrary(IPkcs11Backend backend, bool expectedOmitsValueLen) =>
        WithMlKem(backend, CkpMlKem.CKP_ML_KEM_768, (workspace, mlkem) =>
        {
            using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
            mlkem.Encapsulate(out byte[] ciphertext, out byte[] sharedSecretEnc);

            byte[] first = mlkem.Decapsulate(ciphertext);
            Assert.Equal(sharedSecretEnc, first);
            Assert.Equal(expectedOmitsValueLen, workspace.Library.MlKemDecapsulateOmitsValueLen);

            byte[] second = mlkem.Decapsulate(ciphertext);
            Assert.Equal(sharedSecretEnc, second);
            Assert.Equal(expectedOmitsValueLen, workspace.Library.MlKemDecapsulateOmitsValueLen);
        });
}
