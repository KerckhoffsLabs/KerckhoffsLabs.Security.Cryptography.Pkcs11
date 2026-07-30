using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These tests exercise the gated RSAES-PKCS#1 v1.5 / raw-RSA paths on purpose (the runtime
// AllowInsecure gate is the behaviour under test), so the compile-time warning is suppressed
// for this file only — the per-id suppression the diagnostic exists to enable.
#pragma warning disable KLPKCS11008

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Shared test logic for the RSA PKCS#1 v1.5 signature gate.
/// The gate fires in managed C# before any C_SignInit call, so these tests
/// run on both Mock and SoftHSM backends.
/// </summary>
internal static class SignRsaPkcsTestCases
{
    /// <summary>
    /// Asserts that RSA PKCS#1 v1.5 signing (CKM_RSA_PKCS) throws
    /// <see cref="InsecureOperationException"/> by default (AllowInsecure = false).
    /// </summary>
    internal static void Assert_SignRsaPkcs1V15_GatedByDefault(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var fakeKey = new ObjectHandle(0);
            var mech = new Mechanism(CKM.CKM_RSA_PKCS);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.Sign(mech, fakeKey, []));
            Assert.Equal(CKM.CKM_RSA_PKCS, ex.Mechanism);
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
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
                var mech = new Mechanism(CKM.CKM_RSA_PKCS);
                session.Sign(mech, fakeKey, []);
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
            TestKeys.LogoutIfRequired(backend, session);
            session.CloseSession();
        }
    }
}
