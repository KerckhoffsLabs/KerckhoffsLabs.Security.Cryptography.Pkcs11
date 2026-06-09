using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// DSAPkcs11 against the second real backend (opencryptoki). Unlike SoftHSM (a FIPS build that drops
/// DSA), opencryptoki's software token implements <c>CKM_DSA</c> / <c>CKM_DSA_KEY_PAIR_GEN</c>. A
/// keypair is generated on the token from a fixed FIPS 186-3 2048/256 domain and signatures are
/// cross-checked against the BCL <see cref="DSA"/> using the exported public key.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class DSAPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    // Fixed 2048-bit prime / 256-bit subprime DSA domain parameters (generated with the BCL).
    private static readonly byte[] P = Convert.FromHexString(
        "F2936B4861E422E0CA0A75FD0F4E5F4771302F0B930048297ECF2B58D586436C79D6A4E2D82A8DB56B4C73094FEB91FC204FA0CF01D0EEF11C669E8BC793A9EB5DEA5B7CC8A8A30623539FA2869CBF16D6DDCD087AFEE2CC22A638B0740B7CA00A7835A28A886FE1C3342A1A84FED1F1D2BD2FA9979EA93497A81D11622AE005B31DAC41740C1C22946D26E48CCEFD03C058A74B9089D055BE2846F12B010B08BC07C40595508BB575A8B4180C9ED2BC4A138B896AAF4DFBCC6B7F2E684E612CCA77AD20130021B83AE12151CA226D33E392A076E5F3825974CA8922CC0EB172F1FC312CE31F92F615E7C92ED747F9B3455883C75FEA4C2B4067B483185F90C3");
    private static readonly byte[] Q = Convert.FromHexString(
        "BCFFB514829FFE01A3E790321F7551F74E298660CDC9B5E215F9EEE31025D20B");
    private static readonly byte[] G = Convert.FromHexString(
        "74D6E59535228FFB244180ADBE81BE791C7C86A5B7E3E40D9E80ED9EC767F4E781B8B2359BF9DBE520D7B33B157A92994CFC523AD701C01715A9A67219802FF05E581B5DAB2B14BC4CBEBAEF6CD74A35361A03B8BAE5C7D5E708DEE143E3CA745D1DED52AF461175FD02F2A7BD7C159885707B33540748DAD3B2ADF31C24E532F8BC20663A8FF293D137AA2326C63BCAB9835F716284A5E09CEEF50D8F0B8E33F258E662BC9F6BA4AF996F30898F27CCCF4377A71547B7FF3FF56310D5194766B4BBCDDC5D11928A46BDA6E57BABAA905F8B7184B3906F1AECE20F2B5A7016422B5C52012B0F21EAC655054FAC6F1A56741BB7FDFED40A8B524314EFF8E94B93");

    // The BCL on the Linux runner supports 2048-bit DSA, but keep the same guard pattern as SoftHSM.
    public static bool DsaSupported { get; } = ProbeDsa();

    private static bool ProbeDsa()
    {
        try { using var d = DSA.Create(2048); return true; }
        catch (Exception) { return false; }
    }

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    // Generates a DSA key pair on the token from the fixed domain parameters and hands DSAPkcs11 to the body.
    private void WithDsa(Action<DSAPkcs11> body)
    {
        if (!_backend.Supports(CKM.CKM_DSA))
            throw new SkipTestException("opencryptoki: CKM_DSA not available");

        using var workspace = OpenWorkspace();
        string label = $"octk-dsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_DSA)
            .Label(label).Id(id).Verify()
            .Attribute(CKA.CKA_PRIME, P)
            .Attribute(CKA.CKA_SUBPRIME, Q)
            .Attribute(CKA.CKA_BASE, G)
            .Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_DSA)
            .Label(label).Id(id).Sign().Build();

        var key = workspace.GenerateKey(new Mechanism(CKM.CKM_DSA_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var dsa = new DSAPkcs11(key);
            body(dsa);
        }
        finally
        {
            try { key.Delete(); } catch { /* best-effort */ }
            key.Dispose();
        }
    }

    [ConditionalFact(nameof(Available))]
    public void SignVerifyData_RoundTrips() => WithDsa(dsa =>
    {
        byte[] data = Encoding.UTF8.GetBytes("dsa round trip");
        byte[] sig = dsa.SignData(data, HashAlgorithmName.SHA256);
        Assert.True(dsa.VerifyData(data, sig, HashAlgorithmName.SHA256));

        byte[] tampered = [.. data];
        tampered[0] ^= 0xFF;
        Assert.False(dsa.VerifyData(tampered, sig, HashAlgorithmName.SHA256));
    });

    [ConditionalFact(nameof(Available), nameof(DsaSupported))]
    public void SignData_VerifiesUnderBclWithExportedPublicKey() => WithDsa(dsa =>
    {
        byte[] data = Encoding.UTF8.GetBytes("interop with the BCL");
        byte[] sig = dsa.SignData(data, HashAlgorithmName.SHA256);

        DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
        using var bcl = DSA.Create();
        bcl.ImportParameters(pub);
        Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256));
    });

    [ConditionalFact(nameof(Available))]
    public void CreateSignature_VerifySignature_OverHash_RoundTrips() => WithDsa(dsa =>
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("hash to sign"));
        byte[] sig = dsa.CreateSignature(hash);
        Assert.True(dsa.VerifySignature(hash, sig));
        Assert.Equal(2 * Q.Length, sig.Length); // P1363 r‖s, each q-sized
    });

    [ConditionalFact(nameof(Available))]
    public void ExportParameters_ReturnsProvidedDomain() => WithDsa(dsa =>
    {
        DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
        Assert.Equal(P, pub.P);
        Assert.Equal(Q, pub.Q);
        Assert.Equal(G, pub.G);
        Assert.NotNull(pub.Y);
        Assert.Null(pub.X); // never exports the private value
    });

    [ConditionalFact(nameof(Available))]
    public void ExportParameters_Private_ThrowsInsecure() => WithDsa(dsa =>
        Assert.Throws<InsecureOperationException>(() => dsa.ExportParameters(includePrivateParameters: true)));
}
