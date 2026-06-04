using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>Backend-free argument tests for <see cref="SHA3_384Pkcs11"/>.</summary>
public sealed class SHA3_384Pkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullWorkspace_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new SHA3_384Pkcs11(workspace: null!));
}

/// <summary>
/// SHA3_384Pkcs11 over SoftHSM: token-computed SHA3-384 must match the FIPS 202 vector and the BCL.
/// Not every token implements <c>CKM_SHA3_384</c> (SoftHSM does not), so the known-answer hashes skip
/// when the mechanism is absent and run against a SHA3-capable token.
/// </summary>
[Collection("SoftHsm")]
public sealed class SHA3_384Pkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private void RequireSha3()
    {
        if (!_backend.Supports(CKM.CKM_SHA3_384))
            throw new SkipTestException("Token does not implement CKM_SHA3_384 (SoftHSM has no SHA3 support).");
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_KnownAnswer_MatchesFips202Vector()
    {
        using var workspace = OpenWorkspace();
        using var sha = new SHA3_384Pkcs11(workspace);
        RequireSha3();

        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));

        // NIST FIPS 202 vector for SHA3-384("abc").
        byte[] expected = Convert.FromHexString(
            "EC01498288516FC926459F58E2C6AD8DF9B473CB0FC08C2596DA7CF0E49BE4B298D88CEA927AC7F539F1EDF228376D25");
        Assert.Equal(48, digest.Length);
        Assert.Equal(expected, digest);
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_MatchesBclSha3_384()
    {
        using var workspace = OpenWorkspace();
        using var sha = new SHA3_384Pkcs11(workspace);
        RequireSha3();

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA3_384.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot()
    {
        using var workspace = OpenWorkspace();
        using var sha = new SHA3_384Pkcs11(workspace);
        RequireSha3();

        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        sha.TransformBlock(part1, 0, part1.Length, null, 0);
        sha.TransformFinalBlock(part2, 0, part2.Length);
        byte[] streamed = sha.Hash!;

        Assert.Equal(SHA3_384.HashData(Encoding.UTF8.GetBytes("hello world")), streamed);
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Reuse_AfterInitialize_ProducesFreshHash()
    {
        using var workspace = OpenWorkspace();
        using var sha = new SHA3_384Pkcs11(workspace);
        RequireSha3();

        byte[] first = sha.ComputeHash(Encoding.UTF8.GetBytes("one"));
        byte[] second = sha.ComputeHash(Encoding.UTF8.GetBytes("two")); // ComputeHash calls Initialize
        Assert.Equal(SHA3_384.HashData(Encoding.UTF8.GetBytes("one")), first);
        Assert.Equal(SHA3_384.HashData(Encoding.UTF8.GetBytes("two")), second);
    }
}
