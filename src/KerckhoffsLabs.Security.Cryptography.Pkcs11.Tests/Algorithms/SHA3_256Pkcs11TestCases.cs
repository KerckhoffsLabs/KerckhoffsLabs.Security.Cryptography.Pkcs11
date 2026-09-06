using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic SHA3_256 digest tests, shared by every backend that advertises <c>CKM_SHA3_256</c>.
/// Per-backend classes are thin wrappers binding the xUnit <c>[Collection]</c> fixture and availability
/// gate; a backend that does not advertise the mechanism skips rather than fails.
/// </summary>
internal static class SHA3_256Pkcs11TestCases
{
    // NIST FIPS 202 vector for SHA3_256("abc").
    private static readonly byte[] KnownDigest = Convert.FromHexString(
        "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532");

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    private static void Require(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_SHA3_256))
            throw new SkipTestException("Backend does not advertise CKM_SHA3_256.");
    }

    internal static void Assert_ComputeHash_KnownAnswer(IPkcs11Backend backend)
    {
        Require(backend);
        using var workspace = OpenWorkspace(backend);
        using var hash = new SHA3_256Pkcs11(workspace);

        byte[] digest = hash.ComputeHash(Encoding.UTF8.GetBytes("abc"));
        Assert.Equal(32, digest.Length);
        Assert.Equal(KnownDigest, digest);
    }

    internal static void Assert_ComputeHash_MatchesBcl(IPkcs11Backend backend)
    {
        Require(backend);
        if (!SHA3_256.IsSupported)
            throw new SkipTestException("Host BCL does not support SHA3-256 (needs OpenSSL 3.x or Windows 11+).");
        using var workspace = OpenWorkspace(backend);
        using var hash = new SHA3_256Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA3_256.HashData(data), hash.ComputeHash(data));
    }

    internal static void Assert_ComputeHash_Streamed_MatchesOneShot(IPkcs11Backend backend)
    {
        Require(backend);
        if (!SHA3_256.IsSupported)
            throw new SkipTestException("Host BCL does not support SHA3-256 (needs OpenSSL 3.x or Windows 11+).");
        using var workspace = OpenWorkspace(backend);
        using var hash = new SHA3_256Pkcs11(workspace);

        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        hash.TransformBlock(part1, 0, part1.Length, null, 0);
        hash.TransformFinalBlock(part2, 0, part2.Length);

        Assert.Equal(SHA3_256.HashData(Encoding.UTF8.GetBytes("hello world")), hash.Hash!);
    }

    internal static void Assert_Reuse_AfterInitialize_ProducesFreshHash(IPkcs11Backend backend)
    {
        Require(backend);
        if (!SHA3_256.IsSupported)
            throw new SkipTestException("Host BCL does not support SHA3-256 (needs OpenSSL 3.x or Windows 11+).");
        using var workspace = OpenWorkspace(backend);
        using var hash = new SHA3_256Pkcs11(workspace);

        byte[] first = hash.ComputeHash(Encoding.UTF8.GetBytes("one"));
        byte[] second = hash.ComputeHash(Encoding.UTF8.GetBytes("two")); // ComputeHash calls Initialize
        Assert.Equal(SHA3_256.HashData(Encoding.UTF8.GetBytes("one")), first);
        Assert.Equal(SHA3_256.HashData(Encoding.UTF8.GetBytes("two")), second);
    }
}
