using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

// DSAPkcs11 is intentionally [Obsolete] (DSA is disallowed by FIPS 186-5); exercising it here is deliberate.
#pragma warning disable KLPKCS11006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic DSAPkcs11 tests. A keypair is generated on the token from a fixed FIPS 186-3
/// 2048/256 domain (p, q, g); sign/verify and parameter export run, with signatures cross-checked
/// against the BCL <see cref="DSA"/> from the exported public key. Every CKM_DSA* operation is gated at
/// the mechanism layer (DSA is disallowed), so the functional cases opt into AllowInsecure. Cases skip
/// where the backend does not implement DSA (e.g. opencryptoki, built -DNODSA).
/// </summary>
internal static class DSAPkcs11TestCases
{
    // macOS BCL (DSASecurityTransforms) can't import/verify a 2048-bit DSA key — DSA.Create(2048)
    // throws — so the BCL cross-check can't run there even though SoftHSM signs fine.
    private static readonly bool DsaSupported = ProbeDsa();

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

    // Fixed 2048-bit prime / 256-bit subprime DSA domain parameters (generated with the BCL).
    private static readonly byte[] P = Convert.FromHexString(
        "F2936B4861E422E0CA0A75FD0F4E5F4771302F0B930048297ECF2B58D586436C79D6A4E2D82A8DB56B4C73094FEB91FC204FA0CF01D0EEF11C669E8BC793A9EB5DEA5B7CC8A8A30623539FA2869CBF16D6DDCD087AFEE2CC22A638B0740B7CA00A7835A28A886FE1C3342A1A84FED1F1D2BD2FA9979EA93497A81D11622AE005B31DAC41740C1C22946D26E48CCEFD03C058A74B9089D055BE2846F12B010B08BC07C40595508BB575A8B4180C9ED2BC4A138B896AAF4DFBCC6B7F2E684E612CCA77AD20130021B83AE12151CA226D33E392A076E5F3825974CA8922CC0EB172F1FC312CE31F92F615E7C92ED747F9B3455883C75FEA4C2B4067B483185F90C3");
    private static readonly byte[] Q = Convert.FromHexString(
        "BCFFB514829FFE01A3E790321F7551F74E298660CDC9B5E215F9EEE31025D20B");
    private static readonly byte[] G = Convert.FromHexString(
        "74D6E59535228FFB244180ADBE81BE791C7C86A5B7E3E40D9E80ED9EC767F4E781B8B2359BF9DBE520D7B33B157A92994CFC523AD701C01715A9A67219802FF05E581B5DAB2B14BC4CBEBAEF6CD74A35361A03B8BAE5C7D5E708DEE143E3CA745D1DED52AF461175FD02F2A7BD7C159885707B33540748DAD3B2ADF31C24E532F8BC20663A8FF293D137AA2326C63BCAB9835F716284A5E09CEEF50D8F0B8E33F258E662BC9F6BA4AF996F30898F27CCCF4377A71547B7FF3FF56310D5194766B4BBCDDC5D11928A46BDA6E57BABAA905F8B7184B3906F1AECE20F2B5A7016422B5C52012B0F21EAC655054FAC6F1A56741BB7FDFED40A8B524314EFF8E94B93");

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

    // Generates a DSA key pair on the token from the fixed domain parameters and hands DSAPkcs11 to the
    // body. DSA is FIPS-186-5-disallowed and every CKM_DSA* sign/verify is gated at the mechanism layer,
    // so the functional overload opts into AllowInsecure; the gated-by-default test passes false. Skips
    // where the backend does not implement DSA.
    private static void WithDsa(IPkcs11Backend backend, Action<DSAPkcs11> body)
        => WithDsa(backend, allowInsecure: true, (_, dsa) => body(dsa));

    private static void WithDsa(IPkcs11Backend backend, bool allowInsecure, Action<Pkcs11Workspace, DSAPkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_DSA))
            throw new SkipTestException("Backend does not advertise CKM_DSA.");

        using var workspace = OpenWorkspace(backend);
        if (allowInsecure) workspace.AllowInsecure = true;
        string label = $"dsa-{Guid.NewGuid():N}";
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
            body(workspace, dsa);
        }
        finally
        {
            try { key.Delete(); } catch { /* best-effort */ }
            key.Dispose();
        }
    }

    internal static void Assert_Ctor_NonDsaKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"dsa-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new DSAPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_SignVerifyData_RoundTrips(IPkcs11Backend backend) =>
        WithDsa(backend, dsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("dsa round trip");
            byte[] sig = dsa.SignData(data, HashAlgorithmName.SHA256);
            Assert.True(dsa.VerifyData(data, sig, HashAlgorithmName.SHA256));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(dsa.VerifyData(tampered, sig, HashAlgorithmName.SHA256));
        });

    // DSA is gated at the mechanism layer: signing is refused without AllowInsecure, even though
    // SoftHSM advertises CKM_DSA_SHA256. (Key generation is not gated, so this still sets up.)
    internal static void Assert_SignData_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithDsa(backend, allowInsecure: false, (_, dsa) =>
            Assert.Throws<InsecureOperationException>(
                () => dsa.SignData(Encoding.UTF8.GetBytes("x"), HashAlgorithmName.SHA256)));

    // Vary the hash on the token key (CKM_DSA_SHA* combined, or managed hash + raw CKM_DSA fallback).
    internal static void Assert_SignVerifyData_AcrossHashAlgorithms_RoundTrips(IPkcs11Backend backend, string hashName) =>
        WithDsa(backend, dsa =>
        {
            var hash = new HashAlgorithmName(hashName);
            byte[] data = Encoding.UTF8.GetBytes($"dsa over {hashName}");
            byte[] sig = dsa.SignData(data, hash);
            Assert.True(dsa.VerifyData(data, sig, hash));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(dsa.VerifyData(tampered, sig, hash));
        });

    internal static void Assert_SignData_VerifiesUnderBclWithExportedPublicKey(IPkcs11Backend backend)
    {
        if (!DsaSupported)
            throw new SkipTestException("Platform BCL cannot import a 2048-bit DSA key (macOS DSASecurityTransforms).");

        WithDsa(backend, dsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("interop with the BCL");
            byte[] sig = dsa.SignData(data, HashAlgorithmName.SHA256);

            // Export the token's public parameters and verify the token signature with the BCL.
            DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
            using var bcl = DSA.Create();
            bcl.ImportParameters(pub);
            Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256));
        });
    }

    internal static void Assert_CreateSignature_VerifySignature_OverHash_RoundTrips(IPkcs11Backend backend) =>
        WithDsa(backend, dsa =>
        {
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("hash to sign"));
            byte[] sig = dsa.CreateSignature(hash);
            Assert.True(dsa.VerifySignature(hash, sig));
            Assert.Equal(2 * Q.Length, sig.Length); // P1363 r‖s, each q-sized
        });

    internal static void Assert_ExportParameters_ReturnsProvidedDomain(IPkcs11Backend backend) =>
        WithDsa(backend, dsa =>
        {
            DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
            Assert.Equal(P, pub.P);
            Assert.Equal(Q, pub.Q);
            Assert.Equal(G, pub.G);
            Assert.NotNull(pub.Y);
            Assert.Equal(P.Length, pub.Y!.Length);
            Assert.Null(pub.X); // never exports the private value
        });

    internal static void Assert_ExportParameters_Private_ThrowsInsecure(IPkcs11Backend backend) =>
        WithDsa(backend, dsa =>
            Assert.Throws<InsecureOperationException>(() => dsa.ExportParameters(includePrivateParameters: true)));

    internal static void Assert_ImportParameters_NotSupported(IPkcs11Backend backend) =>
        WithDsa(backend, dsa =>
            Assert.Throws<NotSupportedException>(() => dsa.ImportParameters(new DSAParameters { P = P, Q = Q, G = G })));
}
