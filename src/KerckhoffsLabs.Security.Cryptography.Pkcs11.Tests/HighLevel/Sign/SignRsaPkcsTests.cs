using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Sign;

/// <summary>
/// Shared test logic for the RSA PKCS#1 v1.5 signature gate.
/// The gate fires in managed C# before any C_SignInit call, so these tests
/// run on both Mock and SoftHSM backends.
/// </summary>
internal static class SignRsaPkcsTestCases
{
    /// <summary>
    /// Asserts that <see cref="Session.SignRsaPkcs1V15"/> throws
    /// <see cref="InsecureOperationException"/> by default (AllowInsecure = false).
    /// </summary>
    internal static void Assert_SignRsaPkcs1V15_GatedByDefault(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var fakeKey = new ObjectHandle(0);
#pragma warning disable CS0618 // intentionally testing the obsolete API
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.SignRsaPkcs1V15(fakeKey, Array.Empty<byte>()));
#pragma warning restore CS0618
            Assert.Equal(CKM.CKM_RSA_PKCS, ex.Mechanism);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    /// <summary>
    /// Asserts that setting <c>AllowInsecure = true</c> suppresses the
    /// <see cref="InsecureOperationException"/> gate. Any subsequent PKCS#11
    /// error (bad key handle, etc.) is acceptable — we only verify the gate
    /// did not fire.
    /// </summary>
    internal static void Assert_SignRsaPkcs1V15_AllowInsecureBypassesGate(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        session.AllowInsecure = true;
        try
        {
            var fakeKey = new ObjectHandle(0);
            try
            {
#pragma warning disable CS0618 // intentionally testing the obsolete API
                session.SignRsaPkcs1V15(fakeKey, Array.Empty<byte>());
#pragma warning restore CS0618
            }
            catch (InsecureOperationException)
            {
                Assert.Fail("AllowInsecure=true should have suppressed the gate.");
            }
            catch
            {
                // Any other exception (Pkcs11Exception for bad key handle, etc.) is acceptable —
                // we're only asserting the gate didn't fire.
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
// Concrete test class: Mock backend (gate fires in C# before C_SignInit)
// ---------------------------------------------------------------------------

[Collection("Mock")]
public sealed class SignRsaPkcsTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void SignRsaPkcs1V15_GatedByDefault()
        => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_GatedByDefault(_backend);

    [Fact]
    public void SignRsaPkcs1V15_AllowInsecureBypassesGate()
        => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_AllowInsecureBypassesGate(_backend);
}

// ---------------------------------------------------------------------------
// Concrete test class: SoftHSM backend
// ---------------------------------------------------------------------------

[Collection("SoftHsm")]
public sealed class SignRsaPkcsTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignRsaPkcs1V15_GatedByDefault()
        => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_GatedByDefault(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignRsaPkcs1V15_AllowInsecureBypassesGate()
        => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_AllowInsecureBypassesGate(_backend);
}
