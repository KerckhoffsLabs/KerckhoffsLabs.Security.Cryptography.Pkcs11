using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These tests drive the gated legacy mechanisms/hashes on purpose (the AllowInsecure gate is the
// behaviour under test), so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>
/// Shared test logic for the AES decrypt gate (ECB blocked by default) and opt-in bypass.
/// The insecure-mechanism guard fires in managed code before any P/Invoke call, so these
/// tests run on both backends without requiring real crypto.
/// </summary>
internal static class DecryptAesTestCases
{
    private static readonly byte[] AesKey256 =
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    ];

    /// <summary>
    /// Decrypt using CKM_AES_ECB should throw <see cref="InsecureOperationException"/>
    /// by default. The gate fires before C_DecryptInit, so no real key or ciphertext is
    /// needed — we only need a session-level key handle.
    /// </summary>
    internal static void Assert_AesEcb_GatedByDefault(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var keyHandle = TestKeys.CreateAes256Key(session, AesKey256);
            try
            {
                // Block-aligned ciphertext placeholder; gate fires before it is ever consumed.
                byte[] ciphertext = new byte[16];
                using var mechanism = new Mechanism(CKM.CKM_AES_ECB);

                var ex = Assert.Throws<InsecureOperationException>(() =>
                    session.Decrypt(mechanism, keyHandle, ciphertext));
                Assert.Equal(CKM.CKM_AES_ECB, ex.Mechanism);
            }
            finally
            {
                session.DestroyObject(keyHandle);
            }
        }
        finally
        {
            session.CloseSession();
        }
    }

    /// <summary>
    /// With <c>Session.AllowInsecure</c> set to <c>true</c> the gate is bypassed.
    /// The backend may still fail for unrelated reasons (wrong ciphertext etc.), but MUST
    /// NOT throw <see cref="InsecureOperationException"/>.
    /// </summary>
    internal static void Assert_AesEcb_AllowedWithOptIn(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        session.AllowInsecure = true;
        try
        {
            var keyHandle = TestKeys.CreateAes256Key(session, AesKey256);
            try
            {
                byte[] ciphertext = new byte[16];
                using var mechanism = new Mechanism(CKM.CKM_AES_ECB);

                var ex = Record.Exception(() =>
                    session.Decrypt(mechanism, keyHandle, ciphertext));

                // Gate must NOT be the reason for any exception.
                Assert.False(ex is InsecureOperationException,
                    "Expected gate to be bypassed, but InsecureOperationException was still thrown.");
            }
            finally
            {
                session.DestroyObject(keyHandle);
            }
        }
        finally
        {
            session.CloseSession();
        }
    }
}
