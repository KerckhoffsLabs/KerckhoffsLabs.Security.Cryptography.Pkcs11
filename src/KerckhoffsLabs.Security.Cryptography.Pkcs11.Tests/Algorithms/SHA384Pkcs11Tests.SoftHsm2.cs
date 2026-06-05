using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA384Pkcs11 over SoftHSM: token-computed SHA-384 must match the FIPS vector and the BCL.</summary>
[Collection("SoftHsm")]
public sealed class SHA384Pkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
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
        using var sha = new SHA384Pkcs11(workspace);

        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));

        // NIST FIPS 180-4 vector for SHA-384("abc").
        byte[] expected = Convert.FromHexString(
            "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7");
        Assert.Equal(48, digest.Length);
        Assert.Equal(expected, digest);
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_MatchesBcl()
    {
        using var workspace = OpenWorkspace();
        using var sha = new SHA384Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA384.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot()
    {
        using var workspace = OpenWorkspace();
        using var sha = new SHA384Pkcs11(workspace);

        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        sha.TransformBlock(part1, 0, part1.Length, null, 0);
        sha.TransformFinalBlock(part2, 0, part2.Length);

        Assert.Equal(SHA384.HashData(Encoding.UTF8.GetBytes("hello world")), sha.Hash!);
    }
}
