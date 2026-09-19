using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// CKM_AES_CBC_PAD is unauthenticated and gated by default; it is used here only as a convenient,
// widely-supported mechanism to probe CKA_ENCRYPT/CKA_DECRYPT enforcement, not for its own security
// properties, so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Confirms every supported backend actually enforces the CKA_SIGN/CKA_VERIFY/CKA_ENCRYPT/CKA_DECRYPT
/// capability attributes on symmetric (generic-secret and AES) keys, rather than silently permitting
/// the operation regardless of the attribute's value.
/// </summary>
/// <remarks>
/// Prompted by AWS's "PKCS#11 Compliance Report for CloudHSM SDK 3.2.1" (Galois, Nov 2020), which
/// found CloudHSM's own PKCS#11 library does NOT enforce CKA_SIGN/CKA_VERIFY for AES or
/// CKK_GENERIC_SECRET keys (issues SIGN-1, VERIFY-1) — for clarity, that report notes RSA/EC keys ARE
/// correctly enforced there. That finding is specific to CloudHSM's SDK, a backend this project does
/// not target, so it doesn't transfer directly — but it identified a genuine, previously-untested
/// property worth checking against our own backends. Verified directly (not assumed): NSS, SoftHSM2,
/// and Kryoptic all reject every case here. The exact CKR differs by backend — NSS and Kryoptic return
/// CKR_KEY_TYPE_INCONSISTENT for the two HMAC cases (SoftHSM2 returns the more specific
/// CKR_KEY_FUNCTION_NOT_PERMITTED there; all three agree on CKR_KEY_FUNCTION_NOT_PERMITTED for the AES
/// cases) — legitimate backend variance, matching the "Error Codes" classification the CloudHSM report
/// itself uses for equivalent cases, so these assertions accept any <see cref="Pkcs11Exception"/>
/// rather than pinning one specific CKR.
/// </remarks>
internal static class KeyCapabilityEnforcementTestCases
{
    private static ObjectHandle CreateGenericSecret(Pkcs11Session session, byte[] rawKey, bool sign, bool verify)
    {
        using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var tok = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var s = new ObjectAttribute(CKA.CKA_SIGN, sign);
        using var v = new ObjectAttribute(CKA.CKA_VERIFY, verify);
        using var val = new ObjectAttribute(CKA.CKA_VALUE, rawKey);
        return session.CreateObject([c, t, tok, s, v, val]);
    }

    private static ObjectHandle CreateAes(Pkcs11Session session, byte[] rawKey, bool encrypt, bool decrypt)
    {
        using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var tok = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var e = new ObjectAttribute(CKA.CKA_ENCRYPT, encrypt);
        using var d = new ObjectAttribute(CKA.CKA_DECRYPT, decrypt);
        using var val = new ObjectAttribute(CKA.CKA_VALUE, rawKey);
        return session.CreateObject([c, t, tok, e, d, val]);
    }

    internal static void Assert_Sign_WithSignFalse_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SHA256_HMAC);
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            byte[] rawKey = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(rawKey);
            ObjectHandle key = CreateGenericSecret(session, rawKey, sign: false, verify: true);
            try
            {
                Assert.ThrowsAny<Pkcs11Exception>(() =>
                    session.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), key, "probe"u8.ToArray()));
            }
            finally { session.DestroyObject(key); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.Dispose(); }
    }

    internal static void Assert_Verify_WithVerifyFalse_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SHA256_HMAC);
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            byte[] rawKey = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(rawKey);
            byte[] data = "probe"u8.ToArray();

            // A real, valid MAC — so a backend that fails to enforce CKA_VERIFY would otherwise
            // report a successful verification, not just an unrelated MAC mismatch.
            ObjectHandle signOn = CreateGenericSecret(session, rawKey, sign: true, verify: true);
            byte[] validMac;
            try { validMac = session.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), signOn, data); }
            finally { session.DestroyObject(signOn); }

            ObjectHandle verifyOff = CreateGenericSecret(session, rawKey, sign: false, verify: false);
            try
            {
                Assert.ThrowsAny<Pkcs11Exception>(() =>
                    session.Verify(new Mechanism(CKM.CKM_SHA256_HMAC), verifyOff, data, validMac, out bool _));
            }
            finally { session.DestroyObject(verifyOff); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.Dispose(); }
    }

    internal static void Assert_Encrypt_WithEncryptFalse_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_CBC_PAD);
        var session = TestKeys.OpenLoggedInSession(backend);
        session.AllowInsecure = true;
        try
        {
            byte[] rawKey = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(rawKey);
            byte[] iv = new byte[16];
            System.Security.Cryptography.RandomNumberGenerator.Fill(iv);

            ObjectHandle key = CreateAes(session, rawKey, encrypt: false, decrypt: true);
            try
            {
                Assert.ThrowsAny<Pkcs11Exception>(() =>
                    session.Encrypt(new Mechanism(CKM.CKM_AES_CBC_PAD, iv), key, "probe data"u8.ToArray()));
            }
            finally { session.DestroyObject(key); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.Dispose(); }
    }

    internal static void Assert_Decrypt_WithDecryptFalse_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_CBC_PAD);
        var session = TestKeys.OpenLoggedInSession(backend);
        session.AllowInsecure = true;
        try
        {
            byte[] rawKey = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(rawKey);
            byte[] iv = new byte[16];
            System.Security.Cryptography.RandomNumberGenerator.Fill(iv);
            byte[] data = "probe data"u8.ToArray();

            // A real, valid ciphertext — so a backend that fails to enforce CKA_DECRYPT would
            // otherwise report a successful decryption, not just a padding/tag failure.
            ObjectHandle encryptOn = CreateAes(session, rawKey, encrypt: true, decrypt: true);
            byte[] validCiphertext;
            try { validCiphertext = session.Encrypt(new Mechanism(CKM.CKM_AES_CBC_PAD, iv), encryptOn, data); }
            finally { session.DestroyObject(encryptOn); }

            ObjectHandle decryptOff = CreateAes(session, rawKey, encrypt: false, decrypt: false);
            try
            {
                Assert.ThrowsAny<Pkcs11Exception>(() =>
                    session.Decrypt(new Mechanism(CKM.CKM_AES_CBC_PAD, iv), decryptOff, validCiphertext));
            }
            finally { session.DestroyObject(decryptOff); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.Dispose(); }
    }
}
