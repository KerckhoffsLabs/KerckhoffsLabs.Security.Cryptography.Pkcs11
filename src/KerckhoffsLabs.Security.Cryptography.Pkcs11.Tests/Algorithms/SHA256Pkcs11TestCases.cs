using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic SHA-256 digest tests, shared by every backend that advertises <c>CKM_SHA256</c>.
/// The per-backend classes (<c>SHA256Pkcs11Tests_SoftHsm</c> / <c>_OpenCryptoki</c> / …) are thin
/// wrappers that bind the xUnit <c>[Collection]</c> fixture and the availability gate, then call these.
/// A backend that does not advertise the mechanism skips rather than fails.
/// </summary>
internal static class SHA256Pkcs11TestCases
{
    // NIST FIPS 180-4 vector for SHA-256("abc").
    private static readonly byte[] FipsAbc =
        Convert.FromHexString("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.Library.OpenWorkspace(backend.TokenLabel, CKU.CKU_USER, new SecurePin(backend.UserPin.Span));

    private static void RequireSha256(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_SHA256))
            throw new SkipTestException("Backend does not advertise CKM_SHA256.");
    }

    internal static void Assert_ComputeHash_KnownAnswer_MatchesFips180Vector(IPkcs11Backend backend)
    {
        RequireSha256(backend);
        using var workspace = OpenWorkspace(backend);
        using var sha = new SHA256Pkcs11(workspace);

        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));
        Assert.Equal(32, digest.Length);
        Assert.Equal(FipsAbc, digest);
    }

    internal static void Assert_ComputeHash_MatchesBcl(IPkcs11Backend backend)
    {
        RequireSha256(backend);
        using var workspace = OpenWorkspace(backend);
        using var sha = new SHA256Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA256.HashData(data), sha.ComputeHash(data));
    }

    internal static void Assert_ComputeHash_Streamed_MatchesOneShot(IPkcs11Backend backend)
    {
        RequireSha256(backend);
        using var workspace = OpenWorkspace(backend);
        using var sha = new SHA256Pkcs11(workspace);

        // Feed in chunks via TransformBlock/TransformFinalBlock; result must equal the one-shot hash.
        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        sha.TransformBlock(part1, 0, part1.Length, null, 0);
        sha.TransformFinalBlock(part2, 0, part2.Length);

        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes("hello world")), sha.Hash!);
    }

    internal static void Assert_Reuse_AfterInitialize_ProducesFreshHash(IPkcs11Backend backend)
    {
        RequireSha256(backend);
        using var workspace = OpenWorkspace(backend);
        using var sha = new SHA256Pkcs11(workspace);

        byte[] first = sha.ComputeHash(Encoding.UTF8.GetBytes("one"));
        byte[] second = sha.ComputeHash(Encoding.UTF8.GetBytes("two")); // ComputeHash calls Initialize
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes("one")), first);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes("two")), second);
    }
}
