using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// MD5Pkcs11 is [Obsolete] (broken crypto); exercising it here is deliberate.
#pragma warning disable KLPKCS11001

/// <summary>
/// Backend-agnostic MD5 digest tests. MD5 is gated by the secure-defaults policy (<c>CKM_MD5</c>):
/// blocked by default, computed only under AllowInsecure. The gate fires in managed code before the
/// token, so the gated-by-default case runs on any backend; the AllowInsecure case skips where the
/// token does not advertise <c>CKM_MD5</c>.
/// </summary>
internal static class MD5Pkcs11TestCases
{
    // RFC 1321 / BCL: MD5("abc").
    private static readonly byte[] KnownDigest = Convert.FromHexString("900150983CD24FB0D6963F7D28E17F72");

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    internal static void Assert_ComputeHash_GatedByDefault_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        using var hash = new MD5Pkcs11(workspace);

        var ex = Assert.Throws<InsecureOperationException>(
            () => hash.ComputeHash(Encoding.UTF8.GetBytes("abc")));
        Assert.Equal(CKM.CKM_MD5, ex.Mechanism);
    }

    internal static void Assert_ComputeHash_WithAllowInsecure_MatchesBcl(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_MD5))
            throw new SkipTestException("Backend does not advertise CKM_MD5.");

        using var workspace = OpenWorkspace(backend);
        workspace.AllowInsecure = true;
        using var hash = new MD5Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("abc");
        byte[] digest = hash.ComputeHash(data);
        Assert.Equal(16, digest.Length);
        Assert.Equal(KnownDigest, digest);
        Assert.Equal(MD5.HashData(data), digest);
    }
}
#pragma warning restore KLPKCS11001
