using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SHA3_384Pkcs11 over the in-process <c>ManagedSoftToken</c>. SoftHSM does not implement
/// <c>CKM_SHA3_384</c>, so this is exactly the kind of KAT the managed token unlocks — it computes
/// the digest on the token and cross-checks it against the BCL <see cref="SHA3_384"/> primitive
/// (FIPS 202). The managed token does provide <c>CKM_SHA3_384</c>, so the only gate left is host BCL
/// SHA-3 availability (OpenSSL 3.x / Windows 11+), expressed via <see cref="SHA3_384.IsSupported"/>.
/// </summary>
public sealed class SHA3_384Pkcs11Tests_Managed
{
    public static bool Supported => SHA3_384.IsSupported;

    // === Known-answer tests: ported verbatim from the SoftHsm vectors =====================

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_KnownAnswer_MatchesFips202Vector()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_384Pkcs11(workspace);

        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));

        // NIST FIPS 202 vector for SHA3-384("abc").
        byte[] expected = Convert.FromHexString(
            "EC01498288516FC926459F58E2C6AD8DF9B473CB0FC08C2596DA7CF0E49BE4B298D88CEA927AC7F539F1EDF228376D25");
        Assert.Equal(48, digest.Length);
        Assert.Equal(expected, digest);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_KnownAnswer_EmptyInput()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_384Pkcs11(workspace);

        // NIST: SHA3-384("") =
        // 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004
        byte[] digest = sha.ComputeHash([]);
        Assert.Equal(
            Convert.FromHexString(
                "0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE983A2AC3713831264ADB47FB6BD1E058D5F004"),
            digest);
        Assert.Equal(SHA3_384.HashData([]), digest);
    }

    // === BCL cross-checks ================================================================

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_MatchesBclSha3_384()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_384Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA3_384.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_RandomInput_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_384Pkcs11(workspace);

        byte[] data = RandomNumberGenerator.GetBytes(1024);
        Assert.Equal(SHA3_384.HashData(data), sha.ComputeHash(data));
    }

    // === Streaming / incremental hashing =================================================

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_Streamed_MatchesOneShot()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_384Pkcs11(workspace);

        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        sha.TransformBlock(part1, 0, part1.Length, null, 0);
        sha.TransformFinalBlock(part2, 0, part2.Length);
        byte[] streamed = sha.Hash!;

        Assert.Equal(SHA3_384.HashData(Encoding.UTF8.GetBytes("hello world")), streamed);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_ManyBlocks_MatchesOneShot()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_384Pkcs11(workspace);

        byte[] whole = RandomNumberGenerator.GetBytes(300);
        // Feed in irregular chunks; the buffered one-shot must equal a single hash of the whole.
        int[] sizes = [1, 7, 64, 100, 128];
        int offset = 0;
        foreach (int size in sizes)
        {
            sha.TransformBlock(whole, offset, size, null, 0);
            offset += size;
        }
        sha.TransformFinalBlock(whole, offset, whole.Length - offset);

        Assert.Equal(SHA3_384.HashData(whole), sha.Hash!);
    }

    // === Reuse ===========================================================================

    [ConditionalFact(nameof(Supported))]
    public void Reuse_AfterInitialize_ProducesFreshHash()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_384Pkcs11(workspace);

        byte[] first = sha.ComputeHash(Encoding.UTF8.GetBytes("one"));
        byte[] second = sha.ComputeHash(Encoding.UTF8.GetBytes("two")); // ComputeHash calls Initialize
        Assert.Equal(SHA3_384.HashData(Encoding.UTF8.GetBytes("one")), first);
        Assert.Equal(SHA3_384.HashData(Encoding.UTF8.GetBytes("two")), second);
    }

    [ConditionalFact(nameof(Supported))]
    public void Initialize_DiscardsBufferedInput()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_384Pkcs11(workspace);

        byte[] stale = Encoding.UTF8.GetBytes("discard me");
        sha.TransformBlock(stale, 0, stale.Length, null, 0);
        sha.Initialize(); // resets the buffer so the stale bytes never reach the token

        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));
        Assert.Equal(
            Convert.FromHexString(
                "EC01498288516FC926459F58E2C6AD8DF9B473CB0FC08C2596DA7CF0E49BE4B298D88CEA927AC7F539F1EDF228376D25"),
            digest);
    }

    // === Property surface ================================================================

    [ConditionalFact(nameof(Supported))]
    public void HashSize_Is384Bits()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_384Pkcs11(workspace);

        Assert.Equal(384, sha.HashSize);
    }

    // === Construction and argument validation (throws before any native call) =============

    [Fact]
    public void Ctor_NullWorkspace_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new SHA3_384Pkcs11(null!));
        Assert.Equal("workspace", ex.ParamName);
    }
}
