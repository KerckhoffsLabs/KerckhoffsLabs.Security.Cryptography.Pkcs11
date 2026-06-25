using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

// MLKem (FIPS 203) export-to-PKCS#8 etc. are evaluation-only BCL APIs (SYSLIB5006); suppress here.
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic MLKemPkcs11 (FIPS 203) tests: encapsulate/decapsulate round-trip (extracting the
/// shared secret is gated by the secure-defaults policy), and key-material export (encapsulation key
/// encoding; private export refused). The non-ML-KEM-key constructor check runs anywhere; the
/// real-crypto cases skip where the backend cannot operate ML-KEM (<see cref="IPkcs11Backend.SupportsMlKem"/>).
/// </summary>
internal static class MLKemPkcs11TestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.Library.OpenWorkspace(backend.TokenLabel, CKU.CKU_USER, new SecurePin(backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    // Generates an ML-KEM key pair for the parameter set, wraps it, runs the body, then cleans up.
    // Skips where the backend cannot operate ML-KEM.
    private static void WithMlKem(IPkcs11Backend backend, CkpMlKem parameterSet, Action<Pkcs11Workspace, MLKemPkcs11> body)
    {
        if (!backend.SupportsMlKem)
            throw new SkipTestException("Backend cannot operate ML-KEM (CKM_ML_KEM unavailable).");

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

        var key = workspace.GenerateKey(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var mlkem = new MLKemPkcs11(key);
            body(workspace, mlkem);
        }
        finally
        {
            try { key.Delete(); } catch { /* best-effort cleanup */ }
            key.Dispose();
        }
    }

    internal static void Assert_Ctor_NonMlKemKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
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

    internal static void Assert_EncapsulateDecapsulate_RoundTrips(IPkcs11Backend backend) =>
        WithMlKem(backend, CkpMlKem.CKP_ML_KEM_768, (workspace, mlkem) =>
        {
            // Reading the shared secret is the extract-and-destroy path, gated by the secure-defaults policy.
            workspace.AllowInsecure = true;

            mlkem.Encapsulate(out byte[] ciphertext, out byte[] sharedSecretEnc);
            Assert.Equal(mlkem.Algorithm.CiphertextSizeInBytes, ciphertext.Length);
            Assert.Equal(mlkem.Algorithm.SharedSecretSizeInBytes, sharedSecretEnc.Length);

            byte[] sharedSecretDec = mlkem.Decapsulate(ciphertext);
            Assert.Equal(sharedSecretEnc, sharedSecretDec);
        });

    internal static void Assert_Encapsulate_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithMlKem(backend, CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
            // Without AllowInsecure, extracting the shared secret is refused.
            Assert.Throws<InsecureOperationException>(() => mlkem.Encapsulate(out byte[] _, out byte[] _)));

    internal static void Assert_ExportEncapsulationKey_ReturnsStandardEncoding(IPkcs11Backend backend) =>
        WithMlKem(backend, CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
        {
            byte[] ek = mlkem.ExportEncapsulationKey();
            Assert.Equal(mlkem.Algorithm.EncapsulationKeySizeInBytes, ek.Length);
        });

    internal static void Assert_ExportDecapsulationKey_ThrowsInsecure(IPkcs11Backend backend) =>
        WithMlKem(backend, CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
            Assert.Throws<InsecureOperationException>(() => mlkem.ExportDecapsulationKey()));

    internal static void Assert_ExportPrivateSeed_ThrowsInsecure(IPkcs11Backend backend) =>
        WithMlKem(backend, CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
            Assert.Throws<InsecureOperationException>(() => mlkem.ExportPrivateSeed()));

    internal static void Assert_ExportPkcs8PrivateKey_ThrowsInsecure(IPkcs11Backend backend) =>
        WithMlKem(backend, CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
            Assert.Throws<InsecureOperationException>(() => mlkem.ExportPkcs8PrivateKey()));
}
