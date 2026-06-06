using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SHA256Pkcs11 over the in-process <c>ManagedSoftToken</c> — runs without SoftHSM. The token computes
/// the digest via <c>CKM_SHA256</c> and every result is cross-checked against the BCL
/// <see cref="SHA256"/> primitive (FIPS 180-4). SHA-256 is always supported, so the
/// <see cref="Supported"/> gate is harmless but kept for symmetry with the SHA-3 adapters.
/// </summary>
public sealed class SHA256Pkcs11_Managed
{
    public static bool Supported => true;

    private static Pkcs11Workspace OpenWorkspace(Pkcs11Library library) =>
        ManagedToken.OpenWorkspace(library);

    // === Known-answer + BCL cross-checks =================================================

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_KnownAnswer_MatchesFips180Vector()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha = new SHA256Pkcs11(workspace);

        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));

        // NIST FIPS 180-4 vector for SHA-256("abc").
        byte[] expected = Convert.FromHexString("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
        Assert.Equal(32, digest.Length);
        Assert.Equal(expected, digest);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes("abc")), digest);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_MatchesBclSha256()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha = new SHA256Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA256.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_RandomInput_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha = new SHA256Pkcs11(workspace);

        byte[] data = RandomNumberGenerator.GetBytes(517);
        Assert.Equal(SHA256.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_EmptyInput_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha = new SHA256Pkcs11(workspace);

        byte[] digest = sha.ComputeHash([]);

        // NIST FIPS 180-4 vector for SHA-256("").
        byte[] expected = Convert.FromHexString("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
        Assert.Equal(expected, digest);
        Assert.Equal(SHA256.HashData([]), digest);
    }

    // === Streaming / reuse ===============================================================

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_Streamed_MatchesOneShot()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha = new SHA256Pkcs11(workspace);

        // Feed in chunks via TransformBlock/TransformFinalBlock; result must equal the one-shot hash.
        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        sha.TransformBlock(part1, 0, part1.Length, null, 0);
        sha.TransformFinalBlock(part2, 0, part2.Length);
        byte[] streamed = sha.Hash!;

        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes("hello world")), streamed);
    }

    [ConditionalFact(nameof(Supported))]
    public void Reuse_AfterInitialize_ProducesFreshHash()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha = new SHA256Pkcs11(workspace);

        byte[] first = sha.ComputeHash(Encoding.UTF8.GetBytes("one"));
        byte[] second = sha.ComputeHash(Encoding.UTF8.GetBytes("two")); // ComputeHash calls Initialize
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes("one")), first);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes("two")), second);
    }

    // === Construction and argument validation (run before any native call) ================

    [Fact]
    public void Ctor_NullWorkspace_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new SHA256Pkcs11(null!));
        Assert.Equal("workspace", ex.ParamName);
    }
}
