using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

/// <summary>
/// Helpers for creating ephemeral session-only test keys without depending on
/// Session.GenerateKey* (Phase 4 work). Each helper returns an ObjectHandle;
/// the caller destroys it when done.
/// </summary>
internal static class TestKeys
{
    public static ObjectHandle CreateAes256Key(Session session, byte[] rawKey)
    {
        if (rawKey.Length != 32)
            throw new ArgumentException("AES-256 key must be 32 bytes.", nameof(rawKey));

        using var attrClass   = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrToken   = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrDecrypt = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var attrValue   = new ObjectAttribute(CKA.CKA_VALUE, rawKey);

        var template = new List<ObjectAttribute>
            { attrClass, attrKeyType, attrToken, attrEncrypt, attrDecrypt, attrValue };
        return session.CreateObject(template);
    }

    public static ObjectHandle CreateChaCha20Key(Session session, byte[] rawKey)
    {
        if (rawKey.Length != 32)
            throw new ArgumentException("ChaCha20 key must be 32 bytes.", nameof(rawKey));

        using var attrClass   = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_CHACHA20);
        using var attrToken   = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrDecrypt = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var attrValue   = new ObjectAttribute(CKA.CKA_VALUE, rawKey);

        var template = new List<ObjectAttribute>
            { attrClass, attrKeyType, attrToken, attrEncrypt, attrDecrypt, attrValue };
        return session.CreateObject(template);
    }

    /// <summary>
    /// Opens a R/W session on the backend's slot, logs in as USER, returns it. Caller disposes.
    /// </summary>
    public static Session OpenLoggedInSession(IPkcs11Backend backend)
    {
        var slot = backend.Library.GetSlotList(SlotsType.WithTokenPresent)
            .First(s => (NativeCULong)s.SlotId == backend.SlotId);
        var session = slot.OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_USER, backend.UserPin.ToArray());
        return session;
    }

    /// <summary>
    /// Generates an RSA-2048 key pair as session objects.
    /// Returns (publicHandle, privateHandle).
    /// </summary>
    public static (ObjectHandle pub, ObjectHandle priv) GenerateRsa2048KeyPair(Session session)
    {
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

        using var pubClass   = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var pubToken   = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var pubWrap    = new ObjectAttribute(CKA.CKA_WRAP, true);
        using var pubModBits = new ObjectAttribute(CKA.CKA_MODULUS_BITS, (ulong)2048);
        using var pubExp     = new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 });

        using var privClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var privToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive= new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privDecrypt  = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var privUnwrap   = new ObjectAttribute(CKA.CKA_UNWRAP, true);

        var pubTemplate = new List<ObjectAttribute>
            { pubClass, pubKeyType, pubToken, pubEncrypt, pubWrap, pubModBits, pubExp };
        var privTemplate = new List<ObjectAttribute>
            { privClass, privKeyType, privToken, privSensitive, privDecrypt, privUnwrap };

        session.GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
        return (pub, priv);
    }
}
