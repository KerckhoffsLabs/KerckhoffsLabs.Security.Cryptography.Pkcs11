using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

/// <summary>
/// Helpers for creating ephemeral session-only test keys without depending on
/// Session.GenerateKey* (Phase 4 work). Each helper returns an ObjectHandle;
/// the caller destroys it when done.
/// </summary>
internal static class TestKeys
{
    public static ObjectHandle CreateAes256Key(Pkcs11Session session, byte[] rawKey)
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

    public static ObjectHandle CreateChaCha20Key(Pkcs11Session session, byte[] rawKey)
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
    public static Pkcs11Session OpenLoggedInSession(IPkcs11Backend backend)
    {
        var slot = backend.Library.GetSlotList(SlotsType.WithTokenPresent)
            .First(s => (NativeCULong)s.SlotId == backend.SlotId);
        var session = slot.OpenSession(SessionType.ReadWrite);
        using var pin = new SecurePin(backend.UserPin.Span);
        session.Login(CKU.CKU_USER, pin);
        return session;
    }

    /// <summary>
    /// Generates an RSA-2048 key pair as session objects.
    /// Returns (publicHandle, privateHandle).
    /// </summary>
    public static (ObjectHandle pub, ObjectHandle priv) GenerateRsa2048KeyPair(Pkcs11Session session)
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

    /// <summary>
    /// Generates an RSA-2048 key pair configured for sign/verify (CKA_SIGN + CKA_VERIFY) as session objects.
    /// Returns (publicHandle, privateHandle).
    /// </summary>
    public static (ObjectHandle pub, ObjectHandle priv) GenerateRsa2048SigningKeyPair(Pkcs11Session session)
    {
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

        using var pubClass   = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var pubToken   = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubVerify  = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubModBits = new ObjectAttribute(CKA.CKA_MODULUS_BITS, (ulong)2048);
        using var pubExp     = new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 });

        using var privClass     = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType   = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var privToken     = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privSign      = new ObjectAttribute(CKA.CKA_SIGN, true);

        var pubTemplate  = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubVerify, pubModBits, pubExp };
        var privTemplate = new List<ObjectAttribute> { privClass, privKeyType, privToken, privSensitive, privSign };

        session.GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
        return (pub, priv);
    }

    /// <summary>
    /// Generates an EC key pair on the P-256 (secp256r1) curve as session objects.
    /// Returns (publicHandle, privateHandle).
    /// </summary>
    public static (ObjectHandle pub, ObjectHandle priv) GenerateEcP256KeyPair(Pkcs11Session session)
    {
        using var mechanism = new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN);

        // DER-encoded ASN.1 OID for prime256v1 (1.2.840.10045.3.1.7):
        // 06 08 2A 86 48 CE 3D 03 01 07
        byte[] p256Params = new byte[] { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

        using var pubClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var pubToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubVerify   = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubParams   = new ObjectAttribute(CKA.CKA_EC_PARAMS, p256Params);

        using var privClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var privToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive= new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privSign     = new ObjectAttribute(CKA.CKA_SIGN, true);

        var pubTemplate  = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubVerify, pubParams };
        var privTemplate = new List<ObjectAttribute> { privClass, privKeyType, privToken, privSensitive, privSign };

        session.GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
        return (pub, priv);
    }

    /// <summary>
    /// Generates an Ed25519 key pair as session objects.
    /// Returns (publicHandle, privateHandle). Requires SoftHSM2 2.6+; not supported by pkcs11-mock.
    /// </summary>
    public static (ObjectHandle pub, ObjectHandle priv) GenerateEd25519KeyPair(Pkcs11Session session)
    {
        using var mechanism = new Mechanism(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN);

        // DER-encoded ASN.1 OID for id-Ed25519 (1.3.101.112):
        // 06 03 2B 65 70
        byte[] ed25519Params = new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x70 };

        using var pubClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var pubToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubVerify   = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubParams   = new ObjectAttribute(CKA.CKA_EC_PARAMS, ed25519Params);

        using var privClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var privToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive= new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privSign     = new ObjectAttribute(CKA.CKA_SIGN, true);

        var pubTemplate  = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubVerify, pubParams };
        var privTemplate = new List<ObjectAttribute> { privClass, privKeyType, privToken, privSensitive, privSign };

        session.GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
        return (pub, priv);
    }

    /// <summary>
    /// Generates an Ed448 key pair as session objects.
    /// Returns (publicHandle, privateHandle). Requires SoftHSM2 2.6+; not supported by pkcs11-mock.
    /// </summary>
    public static (ObjectHandle pub, ObjectHandle priv) GenerateEd448KeyPair(Pkcs11Session session)
    {
        using var mechanism = new Mechanism(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN);

        // DER-encoded ASN.1 OID for id-Ed448 (1.3.101.113):
        // 06 03 2B 65 71
        byte[] ed448Params = new byte[] { 0x06, 0x03, 0x2B, 0x65, 0x71 };

        using var pubClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var pubToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubVerify   = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubParams   = new ObjectAttribute(CKA.CKA_EC_PARAMS, ed448Params);

        using var privClass    = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType  = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var privToken    = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive= new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privSign     = new ObjectAttribute(CKA.CKA_SIGN, true);

        var pubTemplate  = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubVerify, pubParams };
        var privTemplate = new List<ObjectAttribute> { privClass, privKeyType, privToken, privSensitive, privSign };

        session.GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
        return (pub, priv);
    }
}
