using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

#pragma warning disable SYSLIB5006 // SLH-DSA is an evaluation-only BCL API.

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SlhDsaPkcs11 over the in-process <c>ManagedSoftToken</c> (no SoftHSM). Uses the SHA2-128f parameter
/// set (the fastest-signing SLH-DSA variant). Gated on <see cref="SlhDsa.IsSupported"/> (OS PQC support).
/// </summary>
public sealed class SlhDsaPkcs11Tests_Managed
{
    public static bool SlhDsaSupported => SlhDsa.IsSupported;

    [ConditionalFact(nameof(SlhDsaSupported))]
    public void SignVerify_RoundTrips_OverManagedToken()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        string label = $"slhdsa-{Guid.NewGuid():N}";
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_SLH_DSA)
            .Label(label).Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128F).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_SLH_DSA)
            .Label(label).Sign().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_SLH_DSA_KEY_PAIR_GEN), privTpl, pubTpl);
        using var slhdsa = new SlhDsaPkcs11(key);

        byte[] data = Encoding.UTF8.GetBytes("SLH-DSA on a managed token");
        byte[] sig = slhdsa.SignData(data);

        Assert.True(slhdsa.VerifyData(data, sig));
        byte[] tampered = (byte[])data.Clone();
        tampered[0] ^= 0xFF;
        Assert.False(slhdsa.VerifyData(tampered, sig));
    }
}
