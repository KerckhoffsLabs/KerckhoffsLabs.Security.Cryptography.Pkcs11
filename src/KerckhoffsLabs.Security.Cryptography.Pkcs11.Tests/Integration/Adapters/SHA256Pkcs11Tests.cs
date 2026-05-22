using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>Backend-free argument tests for <see cref="SHA256Pkcs11"/>.</summary>
public sealed class SHA256Pkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullWorkspace_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new SHA256Pkcs11(workspace: null!));
}

/// <summary>
/// SHA256Pkcs11 over SoftHSM: token-computed SHA-256 must match the FIPS 180-4 vector and the BCL.
/// </summary>
[Collection("SoftHsm")]
public sealed class SHA256Pkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_KnownAnswer_MatchesFips180Vector()
    {
        using var workspace = OpenWorkspace();
        using var sha = new SHA256Pkcs11(workspace);

        byte[] digest = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes("abc"));

        // NIST FIPS 180-4 vector for SHA-256("abc").
        byte[] expected = Convert.FromHexString("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
        Assert.Equal(32, digest.Length);
        Assert.Equal(expected, digest);
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_MatchesBclSha256()
    {
        using var workspace = OpenWorkspace();
        using var sha = new SHA256Pkcs11(workspace);

        byte[] data = System.Text.Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA256.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot()
    {
        using var workspace = OpenWorkspace();
        using var sha = new SHA256Pkcs11(workspace);

        // Feed in chunks via TransformBlock/TransformFinalBlock; result must equal the one-shot hash.
        byte[] part1 = System.Text.Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = System.Text.Encoding.UTF8.GetBytes("world");
        sha.TransformBlock(part1, 0, part1.Length, null, 0);
        sha.TransformFinalBlock(part2, 0, part2.Length);
        byte[] streamed = sha.Hash!;

        Assert.Equal(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("hello world")), streamed);
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Reuse_AfterInitialize_ProducesFreshHash()
    {
        using var workspace = OpenWorkspace();
        using var sha = new SHA256Pkcs11(workspace);

        byte[] first = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes("one"));
        byte[] second = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes("two")); // ComputeHash calls Initialize
        Assert.Equal(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("one")), first);
        Assert.Equal(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("two")), second);
    }
}
