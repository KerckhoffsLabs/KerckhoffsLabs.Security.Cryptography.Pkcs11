using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

#pragma warning disable SYSLIB5006 // ML-KEM is an evaluation-only BCL API.

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// MLKemPkcs11 over the in-process <c>ManagedSoftToken</c>. SoftHSM has no ML-KEM, so its KAT skips —
/// the managed token generates the key pair and runs C_EncapsulateKey/C_DecapsulateKey, with both
/// sides recovering the same shared secret. Reading the shared secret is the extract-and-destroy path,
/// gated by the secure-defaults policy (→ AllowInsecure). Gated on <see cref="MLKem.IsSupported"/>.
/// </summary>
public sealed class MLKemPkcs11Tests_Managed
{
    public static bool MlKemSupported => MLKem.IsSupported;

    [ConditionalFact(nameof(MlKemSupported))]
    public void EncapsulateDecapsulate_RoundTrips_OverManagedToken()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        workspace.AllowInsecure = true;

        string label = $"mlkem-{Guid.NewGuid():N}";
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Label(label)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlKem.CKP_ML_KEM_768).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Label(label)
            .Attribute(CKA.CKA_DECAPSULATE, true).Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), privTpl, pubTpl);
        using var mlkem = new MLKemPkcs11(key);

        mlkem.Encapsulate(out byte[] ciphertext, out byte[] sharedSecretEnc);
        byte[] sharedSecretDec = mlkem.Decapsulate(ciphertext);

        Assert.Equal(sharedSecretEnc, sharedSecretDec);
    }
}
