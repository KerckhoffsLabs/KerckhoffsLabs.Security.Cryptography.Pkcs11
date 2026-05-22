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
    /// Calling <see cref="Session.Encrypt(Mechanism, ObjectHandle, byte[])"/> with an insecure
    /// mechanism must throw <see cref="InsecureOperationException"/> when
    /// <see cref="Session.AllowInsecure"/> is false (the default).
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
    /// With <see cref="Session.AllowInsecure"/> set to <c>true</c> the Encrypt gate is
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
    /// Calling <see cref="Session.Decrypt(Mechanism, ObjectHandle, byte[])"/> with an insecure
    /// mechanism must throw <see cref="InsecureOperationException"/> when
    /// <see cref="Session.AllowInsecure"/> is false (the default).
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
    /// With <see cref="Session.AllowInsecure"/> set to <c>true</c> the Decrypt gate is
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
    /// Calling <see cref="Session.Sign(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/> with an
    /// insecure mechanism must throw <see cref="InsecureOperationException"/> when
    /// <see cref="Session.AllowInsecure"/> is false (the default). The guard fires in managed
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
    /// Calling <see cref="Session.Verify(Mechanism, ObjectHandle, ReadOnlySpan{byte}, ReadOnlySpan{byte}, out bool)"/>
    /// with an insecure mechanism must throw <see cref="InsecureOperationException"/> when
    /// <see cref="Session.AllowInsecure"/> is false (the default). The guard fires in managed
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
    // Digest gate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Calling <see cref="Session.Digest(Mechanism, byte[])"/> with an insecure mechanism must
    /// throw <see cref="InsecureOperationException"/> when <see cref="Session.AllowInsecure"/> is
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
    /// Calling <see cref="Session.GenerateKey(Mechanism, List{ObjectAttribute})"/> with an
    /// insecure mechanism must throw <see cref="InsecureOperationException"/> when
    /// <see cref="Session.AllowInsecure"/> is false (the default). The guard fires in managed
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
    /// Calling <see cref="Session.DeriveKey(Mechanism, ObjectHandle, List{ObjectAttribute})"/>
    /// with an insecure mechanism must throw <see cref="InsecureOperationException"/> when
    /// <see cref="Session.AllowInsecure"/> is false (the default). The guard fires in managed
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

// ---------------------------------------------------------------------------
// Concrete test class: Mock backend
// ---------------------------------------------------------------------------

/// <summary>
/// Insecure-mechanism gate tests against pkcs11-mock.
/// All tests run unconditionally: <see cref="InsecureOperationException"/> is thrown (or
/// bypassed) in managed code before any P/Invoke call, so no real hardware or crypto is
/// required.
/// </summary>
[Collection("Mock")]
public sealed class InsecureOperationGateTests_Mock(MockBackendFixture f)
{
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private readonly MockBackendFixture _backend = f;

    // --- Encrypt gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_AES_ECB)]
    [InlineData((ulong)CKM.CKM_DES_CBC)]
    [InlineData((ulong)CKM.CKM_DES3_CBC)]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_AES_CBC)]   // raw (unauthenticated) AES-CBC
    [InlineData((ulong)CKM.CKM_AES_CTR)]   // unauthenticated AES-CTR
    [InlineData((ulong)CKM.CKM_RC4)]       // broken stream cipher
    [InlineData((ulong)CKM.CKM_RC2_CBC)]   // deprecated cipher
    [InlineData((ulong)CKM.CKM_SEED_CBC)]  // legacy cipher
    [InlineData((ulong)CKM.CKM_CAST128_CBC)]      // legacy 64-bit-block cipher
    [InlineData((ulong)CKM.CKM_RC5_CBC)]        // legacy 64-bit-block cipher
    [InlineData((ulong)CKM.CKM_BLOWFISH_CBC)]   // legacy 64-bit-block cipher
    [InlineData((ulong)CKM.CKM_SKIPJACK_CBC64)] // withdrawn cipher
    public void Encrypt_InsecureMechanismThrows_Mock(ulong mech)
        => InsecureOperationGateTestCases.Assert_Encrypt_InsecureMechanismThrows(_backend, mech);

    [Fact]
    public void Encrypt_AllowInsecure_BypassesGate_Mock()
        => InsecureOperationGateTestCases.Assert_Encrypt_AllowInsecureBypassesGate(_backend);

    // --- Decrypt gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_AES_ECB)]
    [InlineData((ulong)CKM.CKM_DES_CBC)]
    [InlineData((ulong)CKM.CKM_DES3_CBC)]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    public void Decrypt_InsecureMechanismThrows_Mock(ulong mech)
        => InsecureOperationGateTestCases.Assert_Decrypt_InsecureMechanismThrows(_backend, mech);

    [Fact]
    public void Decrypt_AllowInsecure_BypassesGate_Mock()
        => InsecureOperationGateTestCases.Assert_Decrypt_AllowInsecureBypassesGate(_backend);

    // --- Sign gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_MD5_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA1_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_DES_MAC)]
    [InlineData((ulong)CKM.CKM_DES3_MAC)]
    [InlineData((ulong)CKM.CKM_ECDSA_SHA1)]  // SHA-1 in signatures
    [InlineData((ulong)CKM.CKM_SHA_1_HMAC)]  // SHA-1 in MACs
    [InlineData((ulong)CKM.CKM_RSA_X_509)]   // raw RSA, no padding
    public void Sign_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Sign_InsecureMechanismThrows(_backend, mech);

    // --- Verify gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_MD5_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA1_RSA_PKCS)]
    public void Verify_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Verify_InsecureMechanismThrows(_backend, mech);

    // --- Digest gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_MD5)]
    [InlineData((ulong)CKM.CKM_SHA_1)]
    [InlineData((ulong)CKM.CKM_MD2)]        // broken hash
    [InlineData((ulong)CKM.CKM_RIPEMD160)]  // deprecated hash
    public void Digest_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Digest_InsecureMechanismThrows(_backend, mech);

    // --- GenerateKey gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_DES_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_DES2_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_DES3_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_RC4_KEY_GEN)]   // broken cipher key-gen
    [InlineData((ulong)CKM.CKM_RC2_KEY_GEN)]   // deprecated cipher key-gen
    [InlineData((ulong)CKM.CKM_SEED_KEY_GEN)]  // legacy cipher key-gen
    [InlineData((ulong)CKM.CKM_CAST128_KEY_GEN)]    // legacy 64-bit-block cipher
    [InlineData((ulong)CKM.CKM_RC5_KEY_GEN)]      // legacy 64-bit-block cipher
    [InlineData((ulong)CKM.CKM_BLOWFISH_KEY_GEN)] // legacy 64-bit-block cipher
    [InlineData((ulong)CKM.CKM_SKIPJACK_KEY_GEN)] // withdrawn cipher
    public void GenerateKey_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_GenerateKey_InsecureMechanismThrows(_backend, mech);

    // --- DeriveKey gate ---

    [Theory]
    [InlineData((ulong)CKM.CKM_DES3_ECB_ENCRYPT_DATA)]
    [InlineData((ulong)CKM.CKM_DES3_CBC_ENCRYPT_DATA)]
    public void DeriveKey_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_DeriveKey_InsecureMechanismThrows(_backend, mech);
}

// ---------------------------------------------------------------------------
// Concrete test class: SoftHSM backend
// ---------------------------------------------------------------------------

[Collection("SoftHsm")]
public sealed class InsecureOperationGateTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    // --- Encrypt gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_AES_ECB)]
    [InlineData((ulong)CKM.CKM_DES_CBC)]
    [InlineData((ulong)CKM.CKM_DES3_CBC)]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    public void Encrypt_InsecureMechanismThrows_SoftHsm(ulong mech)
        => InsecureOperationGateTestCases.Assert_Encrypt_InsecureMechanismThrows(_backend, mech);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Encrypt_AllowInsecure_BypassesGate_SoftHsm()
        => InsecureOperationGateTestCases.Assert_Encrypt_AllowInsecureBypassesGate(_backend);

    // --- Decrypt gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_AES_ECB)]
    [InlineData((ulong)CKM.CKM_DES_CBC)]
    [InlineData((ulong)CKM.CKM_DES3_CBC)]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    public void Decrypt_InsecureMechanismThrows_SoftHsm(ulong mech)
        => InsecureOperationGateTestCases.Assert_Decrypt_InsecureMechanismThrows(_backend, mech);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decrypt_AllowInsecure_BypassesGate_SoftHsm()
        => InsecureOperationGateTestCases.Assert_Decrypt_AllowInsecureBypassesGate(_backend);

    // --- Sign gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_MD5_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA1_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_DES_MAC)]
    [InlineData((ulong)CKM.CKM_DES3_MAC)]
    public void Sign_InsecureMechanismThrows_SoftHsm(ulong mech)
        => InsecureOperationGateTestCases.Assert_Sign_InsecureMechanismThrows(_backend, mech);

    // --- Verify gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_MD5_RSA_PKCS)]
    [InlineData((ulong)CKM.CKM_SHA1_RSA_PKCS)]
    public void Verify_InsecureMechanismThrows_SoftHsm(ulong mech)
        => InsecureOperationGateTestCases.Assert_Verify_InsecureMechanismThrows(_backend, mech);

    // --- Digest gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_MD5)]
    [InlineData((ulong)CKM.CKM_SHA_1)]
    public void Digest_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_Digest_InsecureMechanismThrows(_backend, mech);

    // --- GenerateKey gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_DES_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_DES2_KEY_GEN)]
    [InlineData((ulong)CKM.CKM_DES3_KEY_GEN)]
    public void GenerateKey_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_GenerateKey_InsecureMechanismThrows(_backend, mech);

    // --- DeriveKey gate ---

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData((ulong)CKM.CKM_DES3_ECB_ENCRYPT_DATA)]
    [InlineData((ulong)CKM.CKM_DES3_CBC_ENCRYPT_DATA)]
    public void DeriveKey_InsecureMechanismThrows(ulong mech)
        => InsecureOperationGateTestCases.Assert_DeriveKey_InsecureMechanismThrows(_backend, mech);
}
