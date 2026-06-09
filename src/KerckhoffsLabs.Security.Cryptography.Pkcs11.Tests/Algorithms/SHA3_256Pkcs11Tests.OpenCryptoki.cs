using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SHA3-256 against the second real backend (opencryptoki). Unlike SoftHSM, opencryptoki's software
/// token implements <c>CKM_SHA3_256</c> (since the 3.27 series), so the token digest is checked
/// against the FIPS 202 vector and the BCL.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class SHA3_256Pkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    // Opens a workspace (logging in) and a digest, runs the body, then disposes both. The workspace
    // MUST be disposed so the per-token login is released — otherwise the next test's C_Login fails
    // with CKR_USER_ALREADY_LOGGED_IN.
    private void WithSha(Action<SHA3_256Pkcs11> body)
    {
        if (!_backend.Supports(CKM.CKM_SHA3_256))
            throw new SkipTestException("opencryptoki: CKM_SHA3_256 not available");
        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));
        using var sha = new SHA3_256Pkcs11(workspace);
        body(sha);
    }

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_KnownAnswer_MatchesFips202Vector() => WithSha(sha =>
    {
        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));
        byte[] expected = Convert.FromHexString("3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532");
        Assert.Equal(32, digest.Length);
        Assert.Equal(expected, digest);
    });

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_MatchesBcl() => WithSha(sha =>
    {
        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA3_256.HashData(data), sha.ComputeHash(data));
    });

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_Streamed_MatchesOneShot() => WithSha(sha =>
    {
        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        sha.TransformBlock(part1, 0, part1.Length, null, 0);
        sha.TransformFinalBlock(part2, 0, part2.Length);
        Assert.Equal(SHA3_256.HashData(Encoding.UTF8.GetBytes("hello world")), sha.Hash!);
    });
}
