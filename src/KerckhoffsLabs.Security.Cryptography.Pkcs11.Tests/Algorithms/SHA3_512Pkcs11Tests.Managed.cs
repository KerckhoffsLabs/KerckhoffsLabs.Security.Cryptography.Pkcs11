using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SHA3_512Pkcs11 over the in-process <c>ManagedSoftToken</c>. SoftHSM does not implement
/// <c>CKM_SHA3_512</c>, so this is exactly the kind of KAT the managed token unlocks — it computes
/// the digest on the token and cross-checks it against the BCL <see cref="SHA3_512"/> primitive
/// (FIPS 202). The managed token does provide <c>CKM_SHA3_512</c>, so the only gate left is host BCL
/// SHA-3 availability (OpenSSL 3.x / Windows 11+), expressed via <see cref="SHA3_512.IsSupported"/>.
/// </summary>
public sealed class SHA3_512Pkcs11Tests_Managed
{
    public static bool Supported => SHA3_512.IsSupported;

    // === Known-answer tests: ported verbatim from the SoftHsm vectors =====================

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_KnownAnswer_MatchesFips202Vector()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_512Pkcs11(workspace);

        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));

        // NIST FIPS 202 vector for SHA3-512("abc").
        byte[] expected = Convert.FromHexString(
            "B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0");
        Assert.Equal(64, digest.Length);
        Assert.Equal(expected, digest);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_KnownAnswer_EmptyInput()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_512Pkcs11(workspace);

        // NIST: SHA3-512("") =
        // a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
        byte[] digest = sha.ComputeHash([]);
        Assert.Equal(
            Convert.FromHexString(
                "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26"),
            digest);
        Assert.Equal(SHA3_512.HashData([]), digest);
    }

    // === BCL cross-checks ================================================================

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_MatchesBclSha3_512()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_512Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA3_512.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_RandomInput_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_512Pkcs11(workspace);

        byte[] data = RandomNumberGenerator.GetBytes(1024);
        Assert.Equal(SHA3_512.HashData(data), sha.ComputeHash(data));
    }

    // === Streaming / incremental hashing =================================================

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_Streamed_MatchesOneShot()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_512Pkcs11(workspace);

        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        sha.TransformBlock(part1, 0, part1.Length, null, 0);
        sha.TransformFinalBlock(part2, 0, part2.Length);
        byte[] streamed = sha.Hash!;

        Assert.Equal(SHA3_512.HashData(Encoding.UTF8.GetBytes("hello world")), streamed);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_ManyBlocks_MatchesOneShot()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_512Pkcs11(workspace);

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

        Assert.Equal(SHA3_512.HashData(whole), sha.Hash!);
    }

    // === Reuse ===========================================================================

    [ConditionalFact(nameof(Supported))]
    public void Reuse_AfterInitialize_ProducesFreshHash()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_512Pkcs11(workspace);

        byte[] first = sha.ComputeHash(Encoding.UTF8.GetBytes("one"));
        byte[] second = sha.ComputeHash(Encoding.UTF8.GetBytes("two")); // ComputeHash calls Initialize
        Assert.Equal(SHA3_512.HashData(Encoding.UTF8.GetBytes("one")), first);
        Assert.Equal(SHA3_512.HashData(Encoding.UTF8.GetBytes("two")), second);
    }

    [ConditionalFact(nameof(Supported))]
    public void Initialize_DiscardsBufferedInput()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_512Pkcs11(workspace);

        byte[] stale = Encoding.UTF8.GetBytes("discard me");
        sha.TransformBlock(stale, 0, stale.Length, null, 0);
        sha.Initialize(); // resets the buffer so the stale bytes never reach the token

        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));
        Assert.Equal(
            Convert.FromHexString(
                "B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0"),
            digest);
    }

    // === Property surface ================================================================

    [ConditionalFact(nameof(Supported))]
    public void HashSize_Is512Bits()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_512Pkcs11(workspace);

        Assert.Equal(512, sha.HashSize);
    }

    // === Construction and argument validation (throws before any native call) =============

    [Fact]
    public void Ctor_NullWorkspace_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new SHA3_512Pkcs11(null!));
        Assert.Equal("workspace", ex.ParamName);
    }
}
