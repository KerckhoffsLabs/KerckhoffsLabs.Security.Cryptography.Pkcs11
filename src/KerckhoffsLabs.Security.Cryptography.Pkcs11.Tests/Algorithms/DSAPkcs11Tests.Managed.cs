using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// DSAPkcs11 over the in-process <c>ManagedSoftToken</c>. The BCL can't generate a DSA key inside a
/// caller-provided (P,Q,G) domain, so a complete BCL key is imported (C_CreateObject) as a public +
/// private object pair linked by CKA_ID; the token reconstructs a live DSA from the attributes. Then
/// sign/verify run on-token (combined CKM_DSA_SHA256, raw r‖s), cross-checked against the BCL.
/// </summary>
public sealed class DSAPkcs11Tests_Managed
{
    // macOS's BCL (DSASecurityTransforms) can't generate a 2048-bit DSA key — DSA.Create(2048)
    // throws — so the managed token can't reconstruct one there. Gate on a one-time probe.
    public static bool DsaSupported { get; } = ProbeDsa();

    private static bool ProbeDsa()
    {
        try
        {
            using var d = DSA.Create(2048);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    [ConditionalFact(nameof(DsaSupported))]
    public void SignVerify_RoundTrips_AndPublicMatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        using var bcl = DSA.Create(2048);
        DSAParameters full = bcl.ExportParameters(includePrivateParameters: true);

        string label = $"dsa-{Guid.NewGuid():N}";
        byte[] id = Guid.NewGuid().ToByteArray();

        // Import the public half first, then the private half (which discovers its companion by CKA_ID).
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_DSA)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_PRIME, full.P!).Attribute(CKA.CKA_SUBPRIME, full.Q!)
            .Attribute(CKA.CKA_BASE, full.G!).Attribute(CKA.CKA_VALUE, full.Y!)
            .Verify().Build();
        _ = workspace.ImportKey(pubTpl);

        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_DSA)
            .Label(label).Id(id)
            .Attribute(CKA.CKA_PRIME, full.P!).Attribute(CKA.CKA_SUBPRIME, full.Q!)
            .Attribute(CKA.CKA_BASE, full.G!).Attribute(CKA.CKA_VALUE, full.X!)
            .Sign().Build();
        using var key = workspace.ImportKey(privTpl);
        using var dsa = new DSAPkcs11(key);

        byte[] data = Encoding.UTF8.GetBytes("DSA signed on a managed token");
        byte[] sig = dsa.SignData(data, HashAlgorithmName.SHA256);

        Assert.True(dsa.VerifyData(data, sig, HashAlgorithmName.SHA256));
        byte[] tampered = (byte[])data.Clone();
        tampered[0] ^= 0xFF;
        Assert.False(dsa.VerifyData(tampered, sig, HashAlgorithmName.SHA256));

        // The exported public domain+value must verify the same signature in the BCL.
        DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
        using var bclVerify = DSA.Create();
        bclVerify.ImportParameters(pub);
        Assert.True(bclVerify.VerifyData(data, sig, HashAlgorithmName.SHA256));
    }
}
