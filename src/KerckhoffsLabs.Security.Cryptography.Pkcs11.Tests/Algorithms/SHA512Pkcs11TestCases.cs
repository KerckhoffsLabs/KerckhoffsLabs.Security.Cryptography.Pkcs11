using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic SHA512 digest tests, shared by every backend that advertises <c>CKM_SHA512</c>.
/// Per-backend classes are thin wrappers binding the xUnit <c>[Collection]</c> fixture and availability
/// gate; a backend that does not advertise the mechanism skips rather than fails.
/// </summary>
internal static class SHA512Pkcs11TestCases
{
    // NIST FIPS 180-4 vector for SHA512("abc").
    private static readonly byte[] KnownDigest = Convert.FromHexString(
        "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F");

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.Library.OpenWorkspace(backend.TokenLabel, CKU.CKU_USER, new SecurePin(backend.UserPin.Span));

    private static void Require(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_SHA512))
            throw new SkipTestException("Backend does not advertise CKM_SHA512.");
    }

    internal static void Assert_ComputeHash_KnownAnswer(IPkcs11Backend backend)
    {
        Require(backend);
        using var workspace = OpenWorkspace(backend);
        using var hash = new SHA512Pkcs11(workspace);

        byte[] digest = hash.ComputeHash(Encoding.UTF8.GetBytes("abc"));
        Assert.Equal(64, digest.Length);
        Assert.Equal(KnownDigest, digest);
    }

    internal static void Assert_ComputeHash_MatchesBcl(IPkcs11Backend backend)
    {
        Require(backend);
        using var workspace = OpenWorkspace(backend);
        using var hash = new SHA512Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA512.HashData(data), hash.ComputeHash(data));
    }

    internal static void Assert_ComputeHash_Streamed_MatchesOneShot(IPkcs11Backend backend)
    {
        Require(backend);
        using var workspace = OpenWorkspace(backend);
        using var hash = new SHA512Pkcs11(workspace);

        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        hash.TransformBlock(part1, 0, part1.Length, null, 0);
        hash.TransformFinalBlock(part2, 0, part2.Length);

        Assert.Equal(SHA512.HashData(Encoding.UTF8.GetBytes("hello world")), hash.Hash!);
    }

    internal static void Assert_Reuse_AfterInitialize_ProducesFreshHash(IPkcs11Backend backend)
    {
        Require(backend);
        using var workspace = OpenWorkspace(backend);
        using var hash = new SHA512Pkcs11(workspace);

        byte[] first = hash.ComputeHash(Encoding.UTF8.GetBytes("one"));
        byte[] second = hash.ComputeHash(Encoding.UTF8.GetBytes("two")); // ComputeHash calls Initialize
        Assert.Equal(SHA512.HashData(Encoding.UTF8.GetBytes("one")), first);
        Assert.Equal(SHA512.HashData(Encoding.UTF8.GetBytes("two")), second);
    }
}
