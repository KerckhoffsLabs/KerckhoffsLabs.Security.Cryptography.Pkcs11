using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// SHA1Pkcs11 is [Obsolete] (broken crypto); exercising it here is deliberate.
#pragma warning disable KLPKCS11002

/// <summary>
/// Backend-agnostic SHA1 digest tests. SHA1 is gated by the secure-defaults policy (<c>CKM_SHA_1</c>):
/// blocked by default, computed only under AllowInsecure. The gate fires in managed code before the
/// token, so the gated-by-default case runs on any backend; the AllowInsecure case skips where the
/// token does not advertise <c>CKM_SHA_1</c>.
/// </summary>
internal static class SHA1Pkcs11TestCases
{
    // FIPS 180-4 / BCL: SHA1("abc").
    private static readonly byte[] KnownDigest = Convert.FromHexString("A9993E364706816ABA3E25717850C26C9CD0D89D");

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    internal static void Assert_ComputeHash_GatedByDefault_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        using var hash = new SHA1Pkcs11(workspace);

        var ex = Assert.Throws<InsecureOperationException>(
            () => hash.ComputeHash(Encoding.UTF8.GetBytes("abc")));
        Assert.Equal(CKM.CKM_SHA_1, ex.Mechanism);
    }

    internal static void Assert_ComputeHash_WithAllowInsecure_MatchesBcl(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_SHA_1))
            throw new SkipTestException("Backend does not advertise CKM_SHA_1.");

        using var workspace = OpenWorkspace(backend);
        workspace.AllowInsecure = true;
        using var hash = new SHA1Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("abc");
        byte[] digest = hash.ComputeHash(data);
        Assert.Equal(20, digest.Length);
        Assert.Equal(KnownDigest, digest);
        Assert.Equal(SHA1.HashData(data), digest);
    }
}
#pragma warning restore KLPKCS11002
