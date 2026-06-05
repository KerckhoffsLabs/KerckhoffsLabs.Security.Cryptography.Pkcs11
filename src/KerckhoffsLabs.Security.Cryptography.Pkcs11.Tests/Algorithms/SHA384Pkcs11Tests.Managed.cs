using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SHA384Pkcs11 over the in-process <c>ManagedSoftToken</c> — runs without SoftHSM. The token computes
/// the digest via <c>CKM_SHA384</c>; every case cross-checks against the BCL <see cref="SHA384"/> and
/// the FIPS 180-4 known-answer vector. SHA-384 is universally supported, but the crypto cases carry a
/// harmless <see cref="Supported"/> gate for symmetry with the SHA-3 adapters.
/// </summary>
public sealed class SHA384Pkcs11_Managed
{
    public static bool Supported => true;

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_KnownAnswer_MatchesFips180Vector()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA384Pkcs11(workspace);

        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));

        // NIST FIPS 180-4 vector for SHA-384("abc").
        byte[] expected = Convert.FromHexString(
            "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7");
        Assert.Equal(48, digest.Length);
        Assert.Equal(expected, digest);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_MatchesBcl_OverManagedToken()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA384Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA384.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_RandomInput_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA384Pkcs11(workspace);

        byte[] data = RandomNumberGenerator.GetBytes(517);
        Assert.Equal(SHA384.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_EmptyInput_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA384Pkcs11(workspace);

        byte[] digest = sha.ComputeHash(Array.Empty<byte>());
        Assert.Equal(SHA384.HashData(Array.Empty<byte>()), digest);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_Streamed_MatchesOneShot()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA384Pkcs11(workspace);

        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        sha.TransformBlock(part1, 0, part1.Length, null, 0);
        sha.TransformFinalBlock(part2, 0, part2.Length);

        Assert.Equal(SHA384.HashData(Encoding.UTF8.GetBytes("hello world")), sha.Hash!);
    }

    [ConditionalFact(nameof(Supported))]
    public void Initialize_ResetsBetweenComputations()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA384Pkcs11(workspace);

        byte[] first = sha.ComputeHash(Encoding.UTF8.GetBytes("first"));
        byte[] second = sha.ComputeHash(Encoding.UTF8.GetBytes("second"));

        Assert.Equal(SHA384.HashData(Encoding.UTF8.GetBytes("first")), first);
        Assert.Equal(SHA384.HashData(Encoding.UTF8.GetBytes("second")), second);
    }

    // === Construction and argument validation (run before any native call) ================

    [Fact]
    public void Ctor_NullWorkspace_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new SHA384Pkcs11(null!));
        Assert.Equal("workspace", ex.ParamName);
    }
}
