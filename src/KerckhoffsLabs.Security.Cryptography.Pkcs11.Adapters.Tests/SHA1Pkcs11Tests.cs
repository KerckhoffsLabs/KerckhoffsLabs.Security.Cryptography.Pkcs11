using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Adapters.Tests;

// SHA1Pkcs11 is [Obsolete] (broken crypto); the gate is the point of the type, so CS0618 is
// suppressed deliberately at the use sites.
#pragma warning disable CS0618

/// <summary>Backend-free argument tests for <see cref="SHA1Pkcs11"/>.</summary>
public sealed class SHA1Pkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullWorkspace_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new SHA1Pkcs11(workspace: null!));
}

/// <summary>
/// SHA1Pkcs11 over SoftHSM: the secure-defaults gate blocks SHA-1 by default (analogous to SHA1Cng
/// under FIPS), and AllowInsecure unlocks token-computed SHA-1 that matches the BCL.
/// </summary>
[Collection("SoftHsm")]
public sealed class SHA1Pkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
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
        using var sha1 = new SHA1Pkcs11(workspace);

        var ex = Assert.Throws<InsecureOperationException>(
            () => sha1.ComputeHash(Encoding.UTF8.GetBytes("abc")));
        Assert.Equal(CKM.CKM_SHA_1, ex.Mechanism);
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_WithAllowInsecure_MatchesBcl()
    {
        using var workspace = OpenWorkspace();
        workspace.AllowInsecure = true;
        using var sha1 = new SHA1Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("abc");
        // FIPS 180-4 / BCL: SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        byte[] expected = Convert.FromHexString("A9993E364706816ABA3E25717850C26C9CD0D89D");
        byte[] digest = sha1.ComputeHash(data);

        Assert.Equal(20, digest.Length);
        Assert.Equal(expected, digest);
        Assert.Equal(SHA1.HashData(data), digest);
    }
}
#pragma warning restore CS0618
