using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These tests drive the gated legacy mechanisms/hashes on purpose (the secure-defaults policy check is the
// behaviour under test), so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary>
/// Shared test logic that parameterises the insecure-mechanism gate over multiple CKM values
/// for both Encrypt and Decrypt. The guard fires in managed code before any P/Invoke call,
/// so a fake <see cref="ObjectHandle"/> (id=0) is sufficient — no real key material is needed.
/// </summary>
internal static class InsecureOperationGateTestCases
{
    // Ends the login a case opened, from the case's finally (its using declaration closes the session after). A
    // logout the module refuses (CKR_USER_NOT_LOGGED_IN, or the session already gone) is tolerated, so cleanup never
    // hides the assertion that failed; any other exception is a real failure and propagates.
    private static void LogOut(Pkcs11SessionCore session)
    {
        try
        {
            session.SendLogout();
        }
        catch (Pkcs11Exception)
        {
            // Not logged in any more, or the session is gone: nothing left to log out.
        }
    }

    // ---------------------------------------------------------------------------
    // Encrypt gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.Encrypt</c> with an insecure
    /// mechanism must throw <see cref="CryptoPolicyViolationException"/> when
    /// the session's crypto policy is <c>CryptoPolicy.Recommended</c> (the default).
    /// </summary>
    internal static void Assert_Encrypt_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        var mechanism = new Mechanism((CKM)mechanismId);
        var fakeHandle = new ObjectHandle(0);

        var ex = Assert.Throws<CryptoPolicyViolationException>(() =>
            session.Encrypt(mechanism, fakeHandle, []));

        Assert.Equal((CKM)mechanismId, ex.Mechanism);
    }

    /// <summary>
    /// With the session's crypto policy set to <c>CryptoPolicy.AllowInsecure</c> the Encrypt gate is
    /// bypassed. The backend may still throw for unrelated reasons (bad handle, etc.), but
    /// MUST NOT throw <see cref="CryptoPolicyViolationException"/>.
    /// </summary>
    internal static void Assert_Encrypt_AllowInsecureBypassesGate(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var mechanism = new Mechanism(CKM.CKM_AES_ECB);
        var fakeHandle = new ObjectHandle(0);

        var ex = Record.Exception(() =>
            session.Encrypt(mechanism, fakeHandle, []));

        Assert.False(ex is CryptoPolicyViolationException,
            "Expected gate to be bypassed, but CryptoPolicyViolationException was still thrown.");
    }

    // ---------------------------------------------------------------------------
    // Decrypt gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.Decrypt</c> with an insecure
    /// mechanism must throw <see cref="CryptoPolicyViolationException"/> when
    /// the session's crypto policy is <c>CryptoPolicy.Recommended</c> (the default).
    /// </summary>
    internal static void Assert_Decrypt_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        var mechanism = new Mechanism((CKM)mechanismId);
        var fakeHandle = new ObjectHandle(0);

        var ex = Assert.Throws<CryptoPolicyViolationException>(() =>
            session.Decrypt(mechanism, fakeHandle, []));

        Assert.Equal((CKM)mechanismId, ex.Mechanism);
    }

    /// <summary>
    /// With the session's crypto policy set to <c>CryptoPolicy.AllowInsecure</c> the Decrypt gate is
    /// bypassed. The backend may still throw for unrelated reasons, but MUST NOT throw
    /// <see cref="CryptoPolicyViolationException"/>.
    /// </summary>
    internal static void Assert_Decrypt_AllowInsecureBypassesGate(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var mechanism = new Mechanism(CKM.CKM_AES_ECB);
        var fakeHandle = new ObjectHandle(0);

        var ex = Record.Exception(() =>
            session.Decrypt(mechanism, fakeHandle, []));

        Assert.False(ex is CryptoPolicyViolationException,
            "Expected gate to be bypassed, but CryptoPolicyViolationException was still thrown.");
    }

    // ---------------------------------------------------------------------------
    // Sign gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.Sign</c> with an
    /// insecure mechanism must throw <see cref="CryptoPolicyViolationException"/> when
    /// the session's crypto policy is <c>CryptoPolicy.Recommended</c> (the default). The guard fires in managed
    /// code before any P/Invoke call, so a fake <see cref="ObjectHandle"/> (id=0) is sufficient.
    /// </summary>
    internal static void Assert_Sign_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var mech = new Mechanism((CKM)mechanismId);
            var fakeHandle = new ObjectHandle(0);
            var ex = Assert.Throws<CryptoPolicyViolationException>(() =>
                session.Sign(mech, fakeHandle, []));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            LogOut(session);
        }
    }

    // ---------------------------------------------------------------------------
    // Verify gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.Verify</c>
    /// with an insecure mechanism must throw <see cref="CryptoPolicyViolationException"/> when
    /// the session's crypto policy is <c>CryptoPolicy.Recommended</c> (the default). The guard fires in managed
    /// code before any P/Invoke call, so a fake <see cref="ObjectHandle"/> (id=0) is sufficient.
    /// </summary>
    internal static void Assert_Verify_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var mech = new Mechanism((CKM)mechanismId);
            var fakeHandle = new ObjectHandle(0);
            var ex = Assert.Throws<CryptoPolicyViolationException>(() =>
                session.Verify(mech, fakeHandle, Array.Empty<byte>(), Array.Empty<byte>()));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            LogOut(session);
        }
    }

    // ---------------------------------------------------------------------------
    // Sign / Verify NOT gated (strong-hash RSA PKCS#1 v1.5 policy)
    // ---------------------------------------------------------------------------

    /// <summary>
    /// A strong-hash RSASSA-PKCS1-v1_5 signature mechanism (e.g. <c>CKM_SHA256_RSA_PKCS</c>) must
    /// NOT be gated: signing with it succeeds past the guard even with the session's crypto policy
    /// left at its <see langword="false"/> default. The backend may still throw for unrelated reasons (the fake
    /// handle is bogus), but MUST NOT throw <see cref="CryptoPolicyViolationException"/>.
    /// </summary>
    internal static void Assert_Sign_MechanismNotGated(IPkcs11Backend backend, ulong mechanismId)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        // The default Recommended policy is deliberately left in place — a strong-hash v1.5 signature
        // is a secure, standard scheme and must not require an insecure opt-in.
        try
        {
            var mech = new Mechanism((CKM)mechanismId);
            var fakeHandle = new ObjectHandle(0);
            var ex = Record.Exception(() => session.Sign(mech, fakeHandle, []));
            Assert.False(ex is CryptoPolicyViolationException,
                $"Mechanism {(CKM)mechanismId} must not be refused under the AllowInsecure policy.");
        }
        finally
        {
            LogOut(session);
        }
    }

    /// <summary>
    /// Companion to <see cref="Assert_Sign_MechanismNotGated"/> for the verify direction. Verifying
    /// a third-party strong-hash v1.5 signature must work without an insecure opt-in.
    /// </summary>
    internal static void Assert_Verify_MechanismNotGated(IPkcs11Backend backend, ulong mechanismId)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var mech = new Mechanism((CKM)mechanismId);
            var fakeHandle = new ObjectHandle(0);
            var ex = Record.Exception(() =>
                session.Verify(mech, fakeHandle, Array.Empty<byte>(), Array.Empty<byte>()));
            Assert.False(ex is CryptoPolicyViolationException,
                $"Mechanism {(CKM)mechanismId} must not be refused under the AllowInsecure policy.");
        }
        finally
        {
            LogOut(session);
        }
    }

    // ---------------------------------------------------------------------------
    // Digest gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.Digest</c> with an insecure mechanism must
    /// throw <see cref="CryptoPolicyViolationException"/> when the session's crypto policy is
    /// false (the default). The guard fires in managed code before any P/Invoke call, so no real
    /// key material is needed.
    /// </summary>
    internal static void Assert_Digest_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var mech = new Mechanism((CKM)mechanismId);
            var ex = Assert.Throws<CryptoPolicyViolationException>(() =>
                session.Digest(mech, []));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            LogOut(session);
        }
    }

    // ---------------------------------------------------------------------------
    // GenerateKey gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.GenerateKey</c> with an
    /// insecure mechanism must throw <see cref="CryptoPolicyViolationException"/> when
    /// the session's crypto policy is <c>CryptoPolicy.Recommended</c> (the default). The guard fires in managed
    /// code before any P/Invoke call, so no real token is needed.
    /// </summary>
    internal static void Assert_GenerateKey_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var mech = new Mechanism((CKM)mechanismId);
            var ex = Assert.Throws<CryptoPolicyViolationException>(() =>
                session.GenerateKey(mech, []));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            LogOut(session);
        }
    }

    // ---------------------------------------------------------------------------
    // DeriveKey gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.DeriveKey</c>
    /// with an insecure mechanism must throw <see cref="CryptoPolicyViolationException"/> when
    /// the session's crypto policy is <c>CryptoPolicy.Recommended</c> (the default). The guard fires in managed
    /// code before any P/Invoke call, so a fake <see cref="ObjectHandle"/> (id=0) is sufficient.
    /// </summary>
    internal static void Assert_DeriveKey_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var mech = new Mechanism((CKM)mechanismId);
            var fakeBase = new ObjectHandle(0);
            var ex = Assert.Throws<CryptoPolicyViolationException>(() =>
                session.DeriveKey(mech, fakeBase, []));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            LogOut(session);
        }
    }
}
