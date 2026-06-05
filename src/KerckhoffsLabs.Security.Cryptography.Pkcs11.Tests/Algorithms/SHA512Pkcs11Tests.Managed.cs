using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SHA512Pkcs11 over the in-process <c>ManagedSoftToken</c> — runs without SoftHSM. The token computes
/// the digest via <c>CKM_SHA512</c> and every result is cross-checked against the BCL
/// <see cref="SHA512"/> primitive (FIPS 180-4). SHA-512 is always supported, so the
/// <see cref="Supported"/> gate is harmless but kept for symmetry with the SHA-3 adapters.
/// </summary>
public sealed class SHA512Pkcs11_Managed
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
        using var sha = new SHA512Pkcs11(workspace);

        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));

        // NIST FIPS 180-4 vector for SHA-512("abc").
        byte[] expected = Convert.FromHexString(
            "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A" +
            "2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F");
        Assert.Equal(64, digest.Length);
        Assert.Equal(expected, digest);
        Assert.Equal(SHA512.HashData(Encoding.UTF8.GetBytes("abc")), digest);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_MatchesBclSha512()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha = new SHA512Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA512.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_RandomInput_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha = new SHA512Pkcs11(workspace);

        byte[] data = RandomNumberGenerator.GetBytes(517);
        Assert.Equal(SHA512.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_EmptyInput_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha = new SHA512Pkcs11(workspace);

        byte[] digest = sha.ComputeHash([]);

        // NIST FIPS 180-4 vector for SHA-512("").
        byte[] expected = Convert.FromHexString(
            "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE" +
            "47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E");
        Assert.Equal(expected, digest);
        Assert.Equal(SHA512.HashData([]), digest);
    }

    // === Streaming / reuse ===============================================================

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_Streamed_MatchesOneShot()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha = new SHA512Pkcs11(workspace);

        // Feed in chunks via TransformBlock/TransformFinalBlock; result must equal the one-shot hash.
        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        sha.TransformBlock(part1, 0, part1.Length, null, 0);
        sha.TransformFinalBlock(part2, 0, part2.Length);
        byte[] streamed = sha.Hash!;

        Assert.Equal(SHA512.HashData(Encoding.UTF8.GetBytes("hello world")), streamed);
    }

    [ConditionalFact(nameof(Supported))]
    public void Reuse_AfterInitialize_ProducesFreshHash()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha = new SHA512Pkcs11(workspace);

        byte[] first = sha.ComputeHash(Encoding.UTF8.GetBytes("one"));
        byte[] second = sha.ComputeHash(Encoding.UTF8.GetBytes("two")); // ComputeHash calls Initialize
        Assert.Equal(SHA512.HashData(Encoding.UTF8.GetBytes("one")), first);
        Assert.Equal(SHA512.HashData(Encoding.UTF8.GetBytes("two")), second);
    }

    [ConditionalFact(nameof(Supported))]
    public void Initialize_ResetsBetweenComputations()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha = new SHA512Pkcs11(workspace);

        byte[] first = sha.ComputeHash(Encoding.UTF8.GetBytes("first"));
        sha.Initialize();
        byte[] second = sha.ComputeHash(Encoding.UTF8.GetBytes("second"));

        Assert.Equal(SHA512.HashData(Encoding.UTF8.GetBytes("first")), first);
        Assert.Equal(SHA512.HashData(Encoding.UTF8.GetBytes("second")), second);
    }

    // === Construction and argument validation (run before any native call) ================

    [Fact]
    public void Ctor_NullWorkspace_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new SHA512Pkcs11(null!));
        Assert.Equal("workspace", ex.ParamName);
    }
}
