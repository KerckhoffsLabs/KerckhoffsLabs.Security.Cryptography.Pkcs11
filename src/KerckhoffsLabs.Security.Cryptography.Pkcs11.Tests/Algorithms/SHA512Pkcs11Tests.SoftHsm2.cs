using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA512Pkcs11 over SoftHSM: token-computed SHA-512 must match the FIPS vector and the BCL.</summary>
[Collection("SoftHsm")]
public sealed class SHA512Pkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
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
        using var sha = new SHA512Pkcs11(workspace);

        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));

        // NIST FIPS 180-4 vector for SHA-512("abc").
        byte[] expected = Convert.FromHexString(
            "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A" +
            "2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F");
        Assert.Equal(64, digest.Length);
        Assert.Equal(expected, digest);
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_MatchesBcl()
    {
        using var workspace = OpenWorkspace();
        using var sha = new SHA512Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA512.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot()
    {
        using var workspace = OpenWorkspace();
        using var sha = new SHA512Pkcs11(workspace);

        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        sha.TransformBlock(part1, 0, part1.Length, null, 0);
        sha.TransformFinalBlock(part2, 0, part2.Length);

        Assert.Equal(SHA512.HashData(Encoding.UTF8.GetBytes("hello world")), sha.Hash!);
    }
}
