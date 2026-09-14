using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SHA3_256Pkcs11 over the in-process <c>ManagedSoftToken</c>. SoftHSM does not implement
/// <c>CKM_SHA3_256</c>, so this is exactly the kind of KAT the managed token unlocks — it computes
/// the digest on the token and cross-checks it against the BCL <see cref="SHA3_256"/> primitive
/// (FIPS 202). The managed token does provide <c>CKM_SHA3_256</c>, so the only gate left is host BCL
/// SHA-3 availability (OpenSSL 3.x / Windows 11+), expressed via <see cref="SHA3_256.IsSupported"/>.
/// </summary>
public sealed class SHA3_256Pkcs11Tests_Managed
{

    // === Known-answer tests: ported verbatim from the SoftHsm vectors =====================

    [ConditionalFact(typeof(SHA3_256), nameof(SHA3_256.IsSupported))]
    public void ComputeHash_KnownAnswer_MatchesFips202Vector()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_256Pkcs11(workspace);

        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));

        // NIST FIPS 202 vector for SHA3-256("abc").
        byte[] expected = Convert.FromHexString("3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532");
        Assert.Equal(32, digest.Length);
        Assert.Equal(expected, digest);
    }

    [ConditionalFact(typeof(SHA3_256), nameof(SHA3_256.IsSupported))]
    public void ComputeHash_KnownAnswer_EmptyInput()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_256Pkcs11(workspace);

        // NIST: SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        byte[] digest = sha.ComputeHash([]);
        Assert.Equal(
            Convert.FromHexString("A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A"),
            digest);
        Assert.Equal(SHA3_256.HashData([]), digest);
    }

    // === BCL cross-checks ================================================================

    [ConditionalFact(typeof(SHA3_256), nameof(SHA3_256.IsSupported))]
    public void ComputeHash_MatchesBclSha3_256()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_256Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA3_256.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(typeof(SHA3_256), nameof(SHA3_256.IsSupported))]
    public void ComputeHash_RandomInput_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_256Pkcs11(workspace);

        byte[] data = RandomNumberGenerator.GetBytes(1024);
        Assert.Equal(SHA3_256.HashData(data), sha.ComputeHash(data));
    }

    // === Streaming / incremental hashing =================================================

    [ConditionalFact(typeof(SHA3_256), nameof(SHA3_256.IsSupported))]
    public void ComputeHash_Streamed_MatchesOneShot()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_256Pkcs11(workspace);

        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        sha.TransformBlock(part1, 0, part1.Length, null, 0);
        sha.TransformFinalBlock(part2, 0, part2.Length);
        byte[] streamed = sha.Hash!;

        Assert.Equal(SHA3_256.HashData(Encoding.UTF8.GetBytes("hello world")), streamed);
    }

    [ConditionalFact(typeof(SHA3_256), nameof(SHA3_256.IsSupported))]
    public void ComputeHash_ManyBlocks_MatchesOneShot()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_256Pkcs11(workspace);

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

        Assert.Equal(SHA3_256.HashData(whole), sha.Hash!);
    }

    // === Reuse ===========================================================================

    [ConditionalFact(typeof(SHA3_256), nameof(SHA3_256.IsSupported))]
    public void Reuse_AfterInitialize_ProducesFreshHash()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_256Pkcs11(workspace);

        byte[] first = sha.ComputeHash(Encoding.UTF8.GetBytes("one"));
        byte[] second = sha.ComputeHash(Encoding.UTF8.GetBytes("two")); // ComputeHash calls Initialize
        Assert.Equal(SHA3_256.HashData(Encoding.UTF8.GetBytes("one")), first);
        Assert.Equal(SHA3_256.HashData(Encoding.UTF8.GetBytes("two")), second);
    }

    [ConditionalFact(typeof(SHA3_256), nameof(SHA3_256.IsSupported))]
    public void Initialize_DiscardsBufferedInput()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_256Pkcs11(workspace);

        byte[] stale = Encoding.UTF8.GetBytes("discard me");
        sha.TransformBlock(stale, 0, stale.Length, null, 0);
        sha.Initialize(); // resets the buffer so the stale bytes never reach the token

        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));
        Assert.Equal(
            Convert.FromHexString("3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532"),
            digest);
    }

    // === Property surface ================================================================

    [ConditionalFact(typeof(SHA3_256), nameof(SHA3_256.IsSupported))]
    public void HashSize_Is256Bits()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_256Pkcs11(workspace);

        Assert.Equal(256, sha.HashSize);
    }

    // === Construction and argument validation (throws before any native call) =============

    [Fact]
    public void Ctor_NullWorkspace_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new SHA3_256Pkcs11(null!));
        Assert.Equal("workspace", ex.ParamName);
    }
}
