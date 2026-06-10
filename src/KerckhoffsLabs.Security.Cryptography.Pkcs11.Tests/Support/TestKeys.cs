using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

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

        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrDecrypt = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, rawKey);

        var template = new List<ObjectAttribute>
            { attrClass, attrKeyType, attrToken, attrEncrypt, attrDecrypt, attrValue };
        return session.CreateObject(template);
    }

    /// <summary>
    /// Generates a random 256-bit AES key with wrap/unwrap usage — a session-only KEK.
    /// </summary>
    public static ObjectHandle GenerateAes256WrappingKey(Pkcs11Session session)
    {
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrValueLen = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrWrap = new ObjectAttribute(CKA.CKA_WRAP, true);
        using var attrUnwrap = new ObjectAttribute(CKA.CKA_UNWRAP, true);

        var template = new List<ObjectAttribute>
            { attrClass, attrKeyType, attrValueLen, attrToken, attrWrap, attrUnwrap };
        using var mechanism = new Mechanism(CKM.CKM_AES_KEY_GEN);
        return session.GenerateKey(mechanism, template);
    }

    public static ObjectHandle CreateChaCha20Key(Pkcs11Session session, byte[] rawKey)
    {
        if (rawKey.Length != 32)
            throw new ArgumentException("ChaCha20 key must be 32 bytes.", nameof(rawKey));

        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_CHACHA20);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrDecrypt = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, rawKey);

        var template = new List<ObjectAttribute>
            { attrClass, attrKeyType, attrToken, attrEncrypt, attrDecrypt, attrValue };
        return session.CreateObject(template);
    }

    /// <summary>
    /// Imports a generic-secret key with a known value (e.g. for HMAC known-answer tests).
    /// </summary>
    public static ObjectHandle CreateGenericSecretKey(Pkcs11Session session, byte[] rawKey)
    {
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrSign = new ObjectAttribute(CKA.CKA_SIGN, true);
        using var attrVerify = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, rawKey);

        var template = new List<ObjectAttribute>
            { attrClass, attrKeyType, attrToken, attrSign, attrVerify, attrValue };
        return session.CreateObject(template);
    }

    // DER-encoded ASN.1 OID for id-Ed25519 (1.3.101.112): 06 03 2B 65 70.
    private static readonly byte[] Ed25519Params = [0x06, 0x03, 0x2B, 0x65, 0x70];

    /// <summary>
    /// Imports an Ed25519 private key from its 32-byte seed (RFC 8032 secret scalar input).
    /// </summary>
    public static ObjectHandle CreateEd25519PrivateKey(Pkcs11Session session, byte[] seed)
    {
        if (seed.Length != 32)
            throw new ArgumentException("Ed25519 seed must be 32 bytes.", nameof(seed));

        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrSign = new ObjectAttribute(CKA.CKA_SIGN, true);
        using var attrParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, Ed25519Params);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, seed);

        var template = new List<ObjectAttribute>
            { attrClass, attrKeyType, attrToken, attrSign, attrParams, attrValue };
        return session.CreateObject(template);
    }

    /// <summary>
    /// Imports an Ed25519 public key from its 32-byte encoded point (RFC 8032 public key).
    /// CKA_EC_POINT is the point wrapped in a DER OCTET STRING, per PKCS#11 EdDSA.
    /// </summary>
    public static ObjectHandle CreateEd25519PublicKey(Pkcs11Session session, byte[] point)
    {
        if (point.Length != 32)
            throw new ArgumentException("Ed25519 public point must be 32 bytes.", nameof(point));
        byte[] ecPoint = [0x04, 0x20, .. point];

        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrVerify = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var attrParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, Ed25519Params);
        using var attrPoint = new ObjectAttribute(CKA.CKA_EC_POINT, ecPoint);

        var template = new List<ObjectAttribute>
            { attrClass, attrKeyType, attrToken, attrVerify, attrParams, attrPoint };
        return session.CreateObject(template);
    }

    /// <summary>
    /// Opens a R/W session on the backend's slot, logs in as USER, returns it. Caller disposes.
    /// </summary>
    public static Pkcs11Session OpenLoggedInSession(IPkcs11Backend backend)
    {
        var slot = backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId == backend.SlotId);
        var session = slot.OpenSession();
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

        using var pubClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var pubToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var pubWrap = new ObjectAttribute(CKA.CKA_WRAP, true);
        using var pubModBits = new ObjectAttribute(CKA.CKA_MODULUS_BITS, (ulong)2048);
        using var pubExp = new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, [0x01, 0x00, 0x01]);

        using var privClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var privToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privDecrypt = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var privUnwrap = new ObjectAttribute(CKA.CKA_UNWRAP, true);

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

        using var pubClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var pubToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubVerify = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubModBits = new ObjectAttribute(CKA.CKA_MODULUS_BITS, (ulong)2048);
        using var pubExp = new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, [0x01, 0x00, 0x01]);

        using var privClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var privToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privSign = new ObjectAttribute(CKA.CKA_SIGN, true);

        var pubTemplate = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubVerify, pubModBits, pubExp };
        var privTemplate = new List<ObjectAttribute> { privClass, privKeyType, privToken, privSensitive, privSign };

        session.GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
        return (pub, priv);
    }

    // DER-encoded ASN.1 OIDs for the NIST P-curves (the CKA_EC_PARAMS value).
    //   P-256 = 1.2.840.10045.3.1.7   P-384 = 1.3.132.0.34   P-521 = 1.3.132.0.35
    public static readonly byte[] EcP256Oid = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    public static readonly byte[] EcP384Oid = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
    public static readonly byte[] EcP521Oid = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];

    /// <summary>Maps a NIST P-curve name ("P-256"/"P-384"/"P-521") to its DER-encoded CKA_EC_PARAMS OID.</summary>
    public static byte[] EcParams(string curve) => curve switch
    {
        "P-256" => EcP256Oid,
        "P-384" => EcP384Oid,
        "P-521" => EcP521Oid,
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unknown EC curve."),
    };

    /// <summary>
    /// Generates an EC key pair on the P-256 (secp256r1) curve as session objects.
    /// Returns (publicHandle, privateHandle).
    /// </summary>
    public static (ObjectHandle pub, ObjectHandle priv) GenerateEcP256KeyPair(Pkcs11Session session)
        => GenerateEcKeyPair(session, EcP256Oid);

    /// <summary>
    /// Generates an EC key pair on the curve identified by the DER-encoded
    /// <paramref name="ecParams"/> OID, as session objects. Returns (publicHandle, privateHandle).
    /// </summary>
    public static (ObjectHandle pub, ObjectHandle priv) GenerateEcKeyPair(Pkcs11Session session, byte[] ecParams)
    {
        using var mechanism = new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN);

        using var pubClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var pubToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubVerify = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, ecParams);

        using var privClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var privToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privSign = new ObjectAttribute(CKA.CKA_SIGN, true);

        var pubTemplate = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubVerify, pubParams };
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
        byte[] ed25519Params = [0x06, 0x03, 0x2B, 0x65, 0x70];

        using var pubClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var pubToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubVerify = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, ed25519Params);

        using var privClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var privToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privSign = new ObjectAttribute(CKA.CKA_SIGN, true);

        var pubTemplate = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubVerify, pubParams };
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
        byte[] ed448Params = [0x06, 0x03, 0x2B, 0x65, 0x71];

        using var pubClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var pubKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var pubToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var pubVerify = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var pubParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, ed448Params);

        using var privClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var privKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS);
        using var privToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var privSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var privSign = new ObjectAttribute(CKA.CKA_SIGN, true);

        var pubTemplate = new List<ObjectAttribute> { pubClass, pubKeyType, pubToken, pubVerify, pubParams };
        var privTemplate = new List<ObjectAttribute> { privClass, privKeyType, privToken, privSensitive, privSign };

        session.GenerateKeyPair(mechanism, pubTemplate, privTemplate, out var pub, out var priv);
        return (pub, priv);
    }

    // === Fixed-key imports for known-answer tests =========================================

    /// <summary>Imports an RSA public key from its big-endian modulus and exponent (verify/encrypt).</summary>
    public static ObjectHandle ImportRsaPublicKey(Pkcs11Session session, byte[] modulus, byte[] exponent)
    {
        using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var tok = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var verify = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var enc = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var n = new ObjectAttribute(CKA.CKA_MODULUS, modulus);
        using var e = new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, exponent);
        return session.CreateObject([c, t, tok, verify, enc, n, e]);
    }

    /// <summary>Imports an RSA private key from its CRT components (big-endian), usable for decrypt.</summary>
    public static ObjectHandle ImportRsaPrivateKey(
        Pkcs11Session session, byte[] modulus, byte[] publicExponent, byte[] privateExponent,
        byte[] prime1, byte[] prime2, byte[] exponent1, byte[] exponent2, byte[] coefficient)
    {
        using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var tok = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var dec = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var n = new ObjectAttribute(CKA.CKA_MODULUS, modulus);
        using var e = new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, publicExponent);
        using var d = new ObjectAttribute(CKA.CKA_PRIVATE_EXPONENT, privateExponent);
        using var p = new ObjectAttribute(CKA.CKA_PRIME_1, prime1);
        using var q = new ObjectAttribute(CKA.CKA_PRIME_2, prime2);
        using var dp = new ObjectAttribute(CKA.CKA_EXPONENT_1, exponent1);
        using var dq = new ObjectAttribute(CKA.CKA_EXPONENT_2, exponent2);
        using var iq = new ObjectAttribute(CKA.CKA_COEFFICIENT, coefficient);
        return session.CreateObject([c, t, tok, dec, n, e, d, p, q, dp, dq, iq]);
    }

    /// <summary>
    /// Encodes a NIST P-curve public point as the PKCS#11 CKA_EC_POINT / ECDH peer-point form:
    /// the uncompressed point (0x04 ‖ X ‖ Y) wrapped in a DER OCTET STRING.
    /// </summary>
    public static byte[] DerEcPoint(byte[] x, byte[] y)
    {
        byte[] raw = [0x04, .. x, .. y];
        return [0x04, (byte)raw.Length, .. raw];
    }

    /// <summary>Imports a NIST P-256 public key from its affine coordinates (verify/derive peer).</summary>
    public static ObjectHandle ImportEcP256PublicKey(Pkcs11Session session, byte[] x, byte[] y)
    {
        using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var tok = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var verify = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var prm = new ObjectAttribute(CKA.CKA_EC_PARAMS, EcP256Oid);
        using var pt = new ObjectAttribute(CKA.CKA_EC_POINT, DerEcPoint(x, y));
        return session.CreateObject([c, t, tok, verify, prm, pt]);
    }

    /// <summary>Imports a NIST P-256 private key from its scalar (big-endian), usable for ECDH derive.</summary>
    public static ObjectHandle ImportEcP256PrivateKey(Pkcs11Session session, byte[] scalar)
    {
        using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var tok = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var derive = new ObjectAttribute(CKA.CKA_DERIVE, true);
        using var prm = new ObjectAttribute(CKA.CKA_EC_PARAMS, EcP256Oid);
        using var v = new ObjectAttribute(CKA.CKA_VALUE, scalar);
        return session.CreateObject([c, t, tok, derive, prm, v]);
    }

    /// <summary>Imports an AES key wrapping key (CKA_WRAP/CKA_UNWRAP) from raw bytes.</summary>
    public static ObjectHandle ImportAesWrappingKey(Pkcs11Session session, byte[] rawKey)
    {
        using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var tok = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var wrap = new ObjectAttribute(CKA.CKA_WRAP, true);
        using var unwrap = new ObjectAttribute(CKA.CKA_UNWRAP, true);
        using var v = new ObjectAttribute(CKA.CKA_VALUE, rawKey);
        return session.CreateObject([c, t, tok, wrap, unwrap, v]);
    }

    /// <summary>Imports an extractable AES key (a wrap target) from raw bytes.</summary>
    public static ObjectHandle ImportExtractableAesKey(Pkcs11Session session, byte[] rawKey)
    {
        using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var tok = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var extract = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
        using var enc = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var v = new ObjectAttribute(CKA.CKA_VALUE, rawKey);
        return session.CreateObject([c, t, tok, extract, enc, v]);
    }
}
