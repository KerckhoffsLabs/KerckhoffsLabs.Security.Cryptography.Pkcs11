using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// ML-KEM (FIPS 203) against the second real backend (opencryptoki). Like ML-DSA, the software token
/// advertises <c>CKM_ML_KEM</c> only when the loaded OpenSSL is ≥ 3.5; the CI job puts OpenSSL 3.5 on
/// the test host's loader path, so these run there and skip elsewhere via <see cref="SkipTestException"/>.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class MLKemPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    // Generates an ML-KEM key pair for the given parameter set, wraps it, runs the body, cleans up.
    private void WithMlKem(CkpMlKem parameterSet, Action<Pkcs11Workspace, MLKemPkcs11> body)
    {
        if (!_backend.Supports(CKM.CKM_ML_KEM))
            throw new SkipTestException("opencryptoki: CKM_ML_KEM not available (needs OpenSSL >= 3.5).");

        using var workspace = OpenWorkspace();
        string label = $"octk-mlkem-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);

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
            try { key.Delete(); } catch { /* best-effort */ }
            key.Dispose();
        }
    }

    [ConditionalFact(nameof(Available))]
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

    [ConditionalFact(nameof(Available))]
    public void Encapsulate_GatedByDefault_Throws() => WithMlKem(CkpMlKem.CKP_ML_KEM_768, (ws, mlkem) =>
    {
        _ = ws;
        Assert.Throws<InsecureOperationException>(() => mlkem.Encapsulate(out byte[] _, out byte[] _));
    });

    [ConditionalFact(nameof(Available))]
    public void ExportEncapsulationKey_ReturnsStandardEncoding() => WithMlKem(CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
    {
        byte[] ek = mlkem.ExportEncapsulationKey();
        Assert.Equal(mlkem.Algorithm.EncapsulationKeySizeInBytes, ek.Length);
    });

    [ConditionalFact(nameof(Available))]
    public void ExportDecapsulationKey_ThrowsInsecure() => WithMlKem(CkpMlKem.CKP_ML_KEM_768, (_, mlkem) =>
        Assert.Throws<InsecureOperationException>(() => mlkem.ExportDecapsulationKey()));
}
