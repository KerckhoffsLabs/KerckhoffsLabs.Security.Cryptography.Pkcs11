using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Digest;

/// <summary>
/// Shared test logic for MD5 and SHA-1 digest gate enforcement.
/// The <see cref="InsecureOperationException"/> gate fires in managed C# before any
/// C_DigestInit call, so these tests run on both Mock and SoftHSM backends.
/// </summary>
internal static class DigestMd5Sha1TestCases
{
    internal static void Assert_Md5_GatedByDefault(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mech = new Mechanism(CKM.CKM_MD5);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.Digest(mech, Array.Empty<byte>()));
            Assert.Equal(CKM.CKM_MD5, ex.Mechanism);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_Sha1_GatedByDefault(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mech = new Mechanism(CKM.CKM_SHA_1);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.Digest(mech, Array.Empty<byte>()));
            Assert.Equal(CKM.CKM_SHA_1, ex.Mechanism);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_Md5_AllowInsecureBypassesGate(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        session.AllowInsecure = true;
        try
        {
            try
            {
                using var mech = new Mechanism(CKM.CKM_MD5);
                session.Digest(mech, Array.Empty<byte>());
            }
            catch (InsecureOperationException)
            {
                Assert.Fail("AllowInsecure=true should have suppressed the gate.");
            }
            catch
            {
                // Any other exception is acceptable — we only assert the gate didn't fire.
            }
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

// ---------------------------------------------------------------------------
// Concrete test class: Mock backend
// (Gate fires in managed C# before C_DigestInit — no real crypto required.)
// ---------------------------------------------------------------------------

[Collection("Mock")]
public sealed class DigestMd5Sha1Tests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void Md5_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Md5_GatedByDefault(_backend);

    [Fact]
    public void Sha1_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Sha1_GatedByDefault(_backend);

    [Fact]
    public void Md5_AllowInsecureBypassesGate() => DigestMd5Sha1TestCases.Assert_Md5_AllowInsecureBypassesGate(_backend);
}

// ---------------------------------------------------------------------------
// Concrete test class: SoftHSM backend
// ---------------------------------------------------------------------------

[Collection("SoftHsm")]
public sealed class DigestMd5Sha1Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Md5_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Md5_GatedByDefault(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Sha1_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Sha1_GatedByDefault(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Md5_AllowInsecureBypassesGate() => DigestMd5Sha1TestCases.Assert_Md5_AllowInsecureBypassesGate(_backend);
}
