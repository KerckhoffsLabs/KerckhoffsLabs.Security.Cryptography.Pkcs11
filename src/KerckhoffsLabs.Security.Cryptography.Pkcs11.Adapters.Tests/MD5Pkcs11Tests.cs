using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Adapters.Tests;

// MD5Pkcs11 is [Obsolete] (broken crypto); the gate is the point of the type, so CS0618 is
// suppressed deliberately at the use sites.
#pragma warning disable CS0618

/// <summary>Backend-free argument tests for <see cref="MD5Pkcs11"/>.</summary>
public sealed class MD5Pkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullWorkspace_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new MD5Pkcs11(workspace: null!));
}

/// <summary>
/// MD5Pkcs11 over SoftHSM: the secure-defaults gate blocks MD5 by default (analogous to MD5Cng
/// under FIPS), and AllowInsecure unlocks token-computed MD5 that matches the BCL.
/// </summary>
[Collection("SoftHsm")]
public sealed class MD5Pkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_GatedByDefault_Throws()
    {
        using var workspace = OpenWorkspace();
        using var md5 = new MD5Pkcs11(workspace);

        var ex = Assert.Throws<InsecureOperationException>(
            () => md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes("abc")));
        Assert.Equal(CKM.CKM_MD5, ex.Mechanism);
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_WithAllowInsecure_MatchesBcl()
    {
        using var workspace = OpenWorkspace();
        workspace.AllowInsecure = true;
        using var md5 = new MD5Pkcs11(workspace);

        byte[] data = System.Text.Encoding.UTF8.GetBytes("abc");
        // RFC 1321 / BCL: MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        byte[] expected = Convert.FromHexString("900150983CD24FB0D6963F7D28E17F72");
        byte[] digest = md5.ComputeHash(data);

        Assert.Equal(16, digest.Length);
        Assert.Equal(expected, digest);
        Assert.Equal(MD5.HashData(data), digest);
    }
}
#pragma warning restore CS0618
