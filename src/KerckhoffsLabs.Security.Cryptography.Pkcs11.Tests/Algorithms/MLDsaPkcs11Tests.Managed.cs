using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

#pragma warning disable SYSLIB5006 // ML-DSA is an evaluation-only BCL API.

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// MLDsaPkcs11 over the in-process <c>ManagedSoftToken</c>. SoftHSM has no ML-DSA, so its KAT skips —
/// the managed token generates the key pair, signs, and verifies entirely via the BCL (gated on
/// <see cref="MLDsa.IsSupported"/>, which needs OS PQC support — OpenSSL 3.5+ / a recent Windows).
/// </summary>
public sealed class MLDsaPkcs11Tests_Managed
{
    public static bool MlDsaSupported => MLDsa.IsSupported;

    [ConditionalTheory(nameof(MlDsaSupported))]
    [InlineData(CkpMlDsa.CKP_ML_DSA_44)]
    [InlineData(CkpMlDsa.CKP_ML_DSA_65)]
    public void SignVerify_RoundTrips_OverManagedToken(CkpMlDsa parameterSet)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        string label = $"mldsa-{Guid.NewGuid():N}";
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA)
            .Label(label).Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA)
            .Label(label).Sign().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), privTpl, pubTpl);
        using var mldsa = new MLDsaPkcs11(key);

        byte[] data = Encoding.UTF8.GetBytes("post-quantum signature on a managed token");
        byte[] sig = mldsa.SignData(data);

        Assert.True(mldsa.VerifyData(data, sig));
        byte[] tampered = (byte[])data.Clone();
        tampered[0] ^= 0xFF;
        Assert.False(mldsa.VerifyData(tampered, sig));
    }
}
