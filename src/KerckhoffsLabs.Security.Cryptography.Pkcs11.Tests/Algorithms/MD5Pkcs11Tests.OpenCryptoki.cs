using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// MD5Pkcs11 is [Obsolete] (broken crypto); the gate is the point of the type, so CS0618 is
// suppressed deliberately at the use sites.
#pragma warning disable CS0618

/// <summary>
/// MD5 digest against the second real backend (opencryptoki). MD5 is gated by the secure-defaults
/// policy; under AllowInsecure the token digest must match the BCL.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class MD5Pkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_UnderAllowInsecure_MatchesBcl()
    {
        if (!_backend.Supports(CKM.CKM_MD5))
            throw new SkipTestException("opencryptoki: CKM_MD5 not available");

        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));
        workspace.AllowInsecure = true;
        using var md5 = new MD5Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("abc");
        Assert.Equal(MD5.HashData(data), md5.ComputeHash(data));
    }
}
#pragma warning restore CS0618
