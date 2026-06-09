using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// SHA1Pkcs11 is [Obsolete] (broken crypto); the gate is the point of the type, so CS0618 is
// suppressed deliberately at the use sites.
#pragma warning disable CS0618

/// <summary>
/// SHA-1 digest against the second real backend (opencryptoki). SHA-1 is gated by the secure-defaults
/// policy; under AllowInsecure the token digest must match the BCL.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class SHA1Pkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_UnderAllowInsecure_MatchesBcl()
    {
        if (!_backend.Supports(CKM.CKM_SHA_1))
            throw new SkipTestException("opencryptoki: CKM_SHA_1 not available");

        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));
        workspace.AllowInsecure = true;
        using var sha1 = new SHA1Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA1.HashData(data), sha1.ComputeHash(data));
    }
}
#pragma warning restore CS0618
