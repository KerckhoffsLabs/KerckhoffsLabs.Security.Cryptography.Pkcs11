using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SHA3-512 against the second real backend (opencryptoki), whose software token implements
/// <c>CKM_SHA3_512</c> (since the 3.27 series). Checked against the FIPS 202 vector and the BCL.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class SHA3_512Pkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private SHA3_512Pkcs11 Open()
    {
        if (!_backend.Supports(CKM.CKM_SHA3_512))
            throw new SkipTestException("opencryptoki: CKM_SHA3_512 not available");
        var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));
        return new SHA3_512Pkcs11(workspace);
    }

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_KnownAnswer_MatchesFips202Vector()
    {
        using var sha = Open();
        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));
        byte[] expected = Convert.FromHexString(
            "B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0");
        Assert.Equal(64, digest.Length);
        Assert.Equal(expected, digest);
    }

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_MatchesBcl()
    {
        using var sha = Open();
        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA3_512.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_Streamed_MatchesOneShot()
    {
        using var sha = Open();
        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        sha.TransformBlock(part1, 0, part1.Length, null, 0);
        sha.TransformFinalBlock(part2, 0, part2.Length);
        Assert.Equal(SHA3_512.HashData(Encoding.UTF8.GetBytes("hello world")), sha.Hash!);
    }
}
