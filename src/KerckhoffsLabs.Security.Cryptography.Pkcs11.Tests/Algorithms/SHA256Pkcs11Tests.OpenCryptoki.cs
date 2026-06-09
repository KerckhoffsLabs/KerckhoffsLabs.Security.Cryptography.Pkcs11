using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SHA-256 digest against the second real backend (opencryptoki): the token digest must match the
/// FIPS 180-4 vector and the BCL.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class SHA256Pkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_MatchesFipsVectorAndBcl()
    {
        if (!_backend.Supports(CKM.CKM_SHA256))
            throw new SkipTestException("opencryptoki: CKM_SHA256 not available");

        using var workspace = OpenWorkspace();
        using var sha = new SHA256Pkcs11(workspace);

        // NIST FIPS 180-4 vector for SHA-256("abc").
        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("abc"));
        Assert.Equal(Convert.FromHexString("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"), digest);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA256.HashData(data), sha.ComputeHash(data));
    }
}
