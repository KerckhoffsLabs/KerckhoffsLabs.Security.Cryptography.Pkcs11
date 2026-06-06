using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary>
/// Shared test logic that parameterises the insecure-mechanism gate over multiple CKM values
/// for both Encrypt and Decrypt. The guard fires in managed code before any P/Invoke call,
/// so a fake <see cref="ObjectHandle"/> (id=0) is sufficient — no real key material is needed.
/// </summary>
internal static class InsecureOperationGateTestCases
{
    // ---------------------------------------------------------------------------
    // Encrypt gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.Encrypt</c> with an insecure
    /// mechanism must throw <see cref="InsecureOperationException"/> when
    /// <c>Session.AllowInsecure</c> is false (the default).
    /// </summary>
    internal static void Assert_Encrypt_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mechanism = new Mechanism((CKM)mechanismId);
            var fakeHandle = new ObjectHandle(0);

            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.Encrypt(mechanism, fakeHandle, []));

            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            session.CloseSession();
        }
    }

    /// <summary>
    /// With <c>Session.AllowInsecure</c> set to <c>true</c> the Encrypt gate is
    /// bypassed. The backend may still throw for unrelated reasons (bad handle, etc.), but
    /// MUST NOT throw <see cref="InsecureOperationException"/>.
    /// </summary>
    internal static void Assert_Encrypt_AllowInsecureBypassesGate(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        session.AllowInsecure = true;
        try
        {
            using var mechanism = new Mechanism(CKM.CKM_AES_ECB);
            var fakeHandle = new ObjectHandle(0);

            var ex = Record.Exception(() =>
                session.Encrypt(mechanism, fakeHandle, []));

            Assert.False(ex is InsecureOperationException,
                "Expected gate to be bypassed, but InsecureOperationException was still thrown.");
        }
        finally
        {
            session.CloseSession();
        }
    }

    // ---------------------------------------------------------------------------
    // Decrypt gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.Decrypt</c> with an insecure
    /// mechanism must throw <see cref="InsecureOperationException"/> when
    /// <c>Session.AllowInsecure</c> is false (the default).
    /// </summary>
    internal static void Assert_Decrypt_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mechanism = new Mechanism((CKM)mechanismId);
            var fakeHandle = new ObjectHandle(0);

            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.Decrypt(mechanism, fakeHandle, []));

            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            session.CloseSession();
        }
    }

    /// <summary>
    /// With <c>Session.AllowInsecure</c> set to <c>true</c> the Decrypt gate is
    /// bypassed. The backend may still throw for unrelated reasons, but MUST NOT throw
    /// <see cref="InsecureOperationException"/>.
    /// </summary>
    internal static void Assert_Decrypt_AllowInsecureBypassesGate(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        session.AllowInsecure = true;
        try
        {
            using var mechanism = new Mechanism(CKM.CKM_AES_ECB);
            var fakeHandle = new ObjectHandle(0);

            var ex = Record.Exception(() =>
                session.Decrypt(mechanism, fakeHandle, []));

            Assert.False(ex is InsecureOperationException,
                "Expected gate to be bypassed, but InsecureOperationException was still thrown.");
        }
        finally
        {
            session.CloseSession();
        }
    }

    // ---------------------------------------------------------------------------
    // Sign gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.Sign</c> with an
    /// insecure mechanism must throw <see cref="InsecureOperationException"/> when
    /// <c>Session.AllowInsecure</c> is false (the default). The guard fires in managed
    /// code before any P/Invoke call, so a fake <see cref="ObjectHandle"/> (id=0) is sufficient.
    /// </summary>
    internal static void Assert_Sign_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mech = new Mechanism((CKM)mechanismId);
            var fakeHandle = new ObjectHandle(0);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.Sign(mech, fakeHandle, []));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            try { session.Logout(); } catch { }
            try { session.CloseSession(); } catch { }
        }
    }

    // ---------------------------------------------------------------------------
    // Verify gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.Verify</c>
    /// with an insecure mechanism must throw <see cref="InsecureOperationException"/> when
    /// <c>Session.AllowInsecure</c> is false (the default). The guard fires in managed
    /// code before any P/Invoke call, so a fake <see cref="ObjectHandle"/> (id=0) is sufficient.
    /// </summary>
    internal static void Assert_Verify_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mech = new Mechanism((CKM)mechanismId);
            var fakeHandle = new ObjectHandle(0);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.Verify(mech, fakeHandle, Array.Empty<byte>(), Array.Empty<byte>(), out _));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            try { session.Logout(); } catch { }
            try { session.CloseSession(); } catch { }
        }
    }

    // ---------------------------------------------------------------------------
    // Sign / Verify NOT gated (strong-hash RSA PKCS#1 v1.5 policy)
    // ---------------------------------------------------------------------------

    /// <summary>
    /// A strong-hash RSASSA-PKCS1-v1_5 signature mechanism (e.g. <c>CKM_SHA256_RSA_PKCS</c>) must
    /// NOT be gated: signing with it succeeds past the guard even with <c>Session.AllowInsecure</c>
    /// left at its <c>false</c> default. The backend may still throw for unrelated reasons (the fake
    /// handle is bogus), but MUST NOT throw <see cref="InsecureOperationException"/>.
    /// </summary>
    internal static void Assert_Sign_MechanismNotGated(IPkcs11Backend backend, ulong mechanismId)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        // AllowInsecure deliberately left false — a strong-hash v1.5 signature is a secure,
        // standard scheme and must not require an insecure opt-in.
        try
        {
            using var mech = new Mechanism((CKM)mechanismId);
            var fakeHandle = new ObjectHandle(0);
            var ex = Record.Exception(() => session.Sign(mech, fakeHandle, []));
            Assert.False(ex is InsecureOperationException,
                $"Mechanism {(CKM)mechanismId} must not be gated by AllowInsecure.");
        }
        finally
        {
            try { session.Logout(); } catch { }
            try { session.CloseSession(); } catch { }
        }
    }

    /// <summary>
    /// Companion to <see cref="Assert_Sign_MechanismNotGated"/> for the verify direction. Verifying
    /// a third-party strong-hash v1.5 signature must work without an insecure opt-in.
    /// </summary>
    internal static void Assert_Verify_MechanismNotGated(IPkcs11Backend backend, ulong mechanismId)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mech = new Mechanism((CKM)mechanismId);
            var fakeHandle = new ObjectHandle(0);
            var ex = Record.Exception(() =>
                session.Verify(mech, fakeHandle, Array.Empty<byte>(), Array.Empty<byte>(), out _));
            Assert.False(ex is InsecureOperationException,
                $"Mechanism {(CKM)mechanismId} must not be gated by AllowInsecure.");
        }
        finally
        {
            try { session.Logout(); } catch { }
            try { session.CloseSession(); } catch { }
        }
    }

    // ---------------------------------------------------------------------------
    // Digest gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.Digest</c> with an insecure mechanism must
    /// throw <see cref="InsecureOperationException"/> when <c>Session.AllowInsecure</c> is
    /// false (the default). The guard fires in managed code before any P/Invoke call, so no real
    /// key material is needed.
    /// </summary>
    internal static void Assert_Digest_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mech = new Mechanism((CKM)mechanismId);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.Digest(mech, []));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            try { session.Logout(); } catch { }
            try { session.CloseSession(); } catch { }
        }
    }

    // ---------------------------------------------------------------------------
    // GenerateKey gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.GenerateKey</c> with an
    /// insecure mechanism must throw <see cref="InsecureOperationException"/> when
    /// <c>Session.AllowInsecure</c> is false (the default). The guard fires in managed
    /// code before any P/Invoke call, so no real token is needed.
    /// </summary>
    internal static void Assert_GenerateKey_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mech = new Mechanism((CKM)mechanismId);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.GenerateKey(mech, []));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            try { session.Logout(); } catch { }
            try { session.CloseSession(); } catch { }
        }
    }

    // ---------------------------------------------------------------------------
    // DeriveKey gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <c>Session.DeriveKey</c>
    /// with an insecure mechanism must throw <see cref="InsecureOperationException"/> when
    /// <c>Session.AllowInsecure</c> is false (the default). The guard fires in managed
    /// code before any P/Invoke call, so a fake <see cref="ObjectHandle"/> (id=0) is sufficient.
    /// </summary>
    internal static void Assert_DeriveKey_InsecureMechanismThrows(IPkcs11Backend backend, ulong mechanismId)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var mech = new Mechanism((CKM)mechanismId);
            var fakeBase = new ObjectHandle(0);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.DeriveKey(mech, fakeBase, []));
            Assert.Equal((CKM)mechanismId, ex.Mechanism);
        }
        finally
        {
            try { session.Logout(); } catch { }
            try { session.CloseSession(); } catch { }
        }
    }
}
