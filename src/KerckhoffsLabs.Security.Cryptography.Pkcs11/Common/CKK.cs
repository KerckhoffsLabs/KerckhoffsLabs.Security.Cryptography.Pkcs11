using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Key types
/// </summary>
public enum CKK : uint
{
    /// <summary>
    /// RSA key
    /// </summary>
    CKK_RSA = 0x00000000,

    /// <summary>
    /// DSA key
    /// </summary>
    CKK_DSA = 0x00000001,

    /// <summary>
    /// DH (Diffie-Hellman) key
    /// </summary>
    CKK_DH = 0x00000002,
    
    /// <summary>
    /// EC (Elliptic Curve) key
    /// </summary>
    CKK_ECDSA = 0x00000003,

    /// <summary>
    /// EC (Elliptic Curve) key
    /// </summary>
    CKK_EC = 0x00000003,

    /// <summary>
    /// X9.42 Diffie-Hellman public keys
    /// </summary>
    CKK_X9_42_DH = 0x00000004,

    /// <summary>
    /// KEA keys
    /// </summary>
    CKK_KEA = 0x00000005,

    /// <summary>
    /// Generic secret key
    /// </summary>
    CKK_GENERIC_SECRET = 0x00000010,

    /// <summary>
    /// RC2 key
    /// </summary>
    CKK_RC2 = 0x00000011,

    /// <summary>
    /// RC4 key
    /// </summary>
    CKK_RC4 = 0x00000012,

    /// <summary>
    /// Single-length DES key
    /// </summary>
    CKK_DES = 0x00000013,

    /// <summary>
    /// Double-length DES key
    /// </summary>
    CKK_DES2 = 0x00000014,

    /// <summary>
    /// Triple-length DES key
    /// </summary>
    CKK_DES3 = 0x00000015,
    
    /// <summary>
    /// CAST key
    /// </summary>
    CKK_CAST = 0x00000016,

    /// <summary>
    /// CAST3 key
    /// </summary>
    CKK_CAST3 = 0x00000017,

    /// <summary>
    /// CAST128 key
    /// </summary>
    CKK_CAST5 = 0x00000018,

    /// <summary>
    /// CAST128 key
    /// </summary>
    CKK_CAST128 = 0x00000018,
    
    /// <summary>
    /// RC5 key
    /// </summary>
    CKK_RC5 = 0x00000019,

    /// <summary>
    /// IDEA key
    /// </summary>
    CKK_IDEA = 0x0000001A,

    /// <summary>
    /// Single-length MEK or a TEK
    /// </summary>
    CKK_SKIPJACK = 0x0000001B,

    /// <summary>
    /// Single-length BATON key
    /// </summary>
    CKK_BATON = 0x0000001C,

    /// <summary>
    /// Single-length JUNIPER key
    /// </summary>
    CKK_JUNIPER = 0x0000001D,

    /// <summary>
    /// Single-length CDMF key
    /// </summary>
    CKK_CDMF = 0x0000001E,

    /// <summary>
    /// AES key
    /// </summary>
    CKK_AES = 0x0000001F,

    /// <summary>
    /// Blowfish key
    /// </summary>
    CKK_BLOWFISH = 0x00000020,

    /// <summary>
    /// Twofish key
    /// </summary>
    CKK_TWOFISH = 0x00000021,

    /// <summary>
    /// RSA SecurID secret key
    /// </summary>
    CKK_SECURID = 0x00000022,

    /// <summary>
    /// Generic secret key and associated counter value
    /// </summary>
    CKK_HOTP = 0x00000023,

    /// <summary>
    /// ActivIdentity ACTI secret key
    /// </summary>
    CKK_ACTI = 0x00000024,

    /// <summary>
    /// Camellia key
    /// </summary>
    CKK_CAMELLIA = 0x00000025,
    
    /// <summary>
    /// ARIA key
    /// </summary>
    CKK_ARIA = 0x00000026,

    /// <summary>
    /// MD5 HMAC key
    /// </summary>
    CKK_MD5_HMAC = 0x00000027,

    /// <summary>
    /// SHA-1 HMAC key
    /// </summary>
    CKK_SHA_1_HMAC = 0x00000028,

    /// <summary>
    /// RIPE-MD 128 HMAC key
    /// </summary>
    CKK_RIPEMD128_HMAC = 0x00000029,

    /// <summary>
    /// RIPE-MD 160 HMAC key
    /// </summary>
    CKK_RIPEMD160_HMAC = 0x0000002A,

    /// <summary>
    /// SHA-256 HMAC key
    /// </summary>
    CKK_SHA256_HMAC = 0x0000002B,

    /// <summary>
    /// SHA-384 HMAC key
    /// </summary>
    CKK_SHA384_HMAC = 0x0000002C,

    /// <summary>
    /// SHA-512 HMAC key
    /// </summary>
    CKK_SHA512_HMAC = 0x0000002D,

    /// <summary>
    /// SHA-224 HMAC key
    /// </summary>
    CKK_SHA224_HMAC = 0x0000002E,

    /// <summary>
    /// SEED secret key
    /// </summary>
    CKK_SEED = 0x0000002F,

    /// <summary>
    /// GOST R 34.10-2001 key
    /// </summary>
    CKK_GOSTR3410 = 0x00000030,

    /// <summary>
    /// GOST R 34.11-94 key or domain parameter
    /// </summary>
    CKK_GOSTR3411 = 0x00000031,

    /// <summary>
    /// GOST 28147-89 key or domain parameter
    /// </summary>
    CKK_GOST28147 = 0x00000032,

    /// <summary>
    /// ChaCha20 symmetric key (PKCS#11 v3.0 §10.7)
    /// </summary>
    CKK_CHACHA20 = 0x00000033,

    /// <summary>Edwards-curve key (Ed25519, Ed448). PKCS#11 v3.0 §10.7.</summary>
    CKK_EC_EDWARDS = 0x00000040,

    /// <summary>
    /// Poly1305 MAC key (PKCS#11 v3.0)
    /// </summary>
    CKK_POLY1305 = 0x00000034,

    /// <summary>
    /// AES-XTS double-length key (PKCS#11 v3.0)
    /// </summary>
    CKK_AES_XTS = 0x00000035,

    /// <summary>
    /// SHA3-224 HMAC key (PKCS#11 v3.0)
    /// </summary>
    CKK_SHA3_224_HMAC = 0x00000036,

    /// <summary>
    /// SHA3-256 HMAC key (PKCS#11 v3.0)
    /// </summary>
    CKK_SHA3_256_HMAC = 0x00000037,

    /// <summary>
    /// SHA3-384 HMAC key (PKCS#11 v3.0)
    /// </summary>
    CKK_SHA3_384_HMAC = 0x00000038,

    /// <summary>
    /// SHA3-512 HMAC key (PKCS#11 v3.0)
    /// </summary>
    CKK_SHA3_512_HMAC = 0x00000039,

    /// <summary>
    /// BLAKE2b-160 HMAC key (PKCS#11 v3.0)
    /// </summary>
    CKK_BLAKE2B_160_HMAC = 0x0000003A,

    /// <summary>
    /// BLAKE2b-256 HMAC key (PKCS#11 v3.0)
    /// </summary>
    CKK_BLAKE2B_256_HMAC = 0x0000003B,

    /// <summary>
    /// BLAKE2b-384 HMAC key (PKCS#11 v3.0)
    /// </summary>
    CKK_BLAKE2B_384_HMAC = 0x0000003C,

    /// <summary>
    /// BLAKE2b-512 HMAC key (PKCS#11 v3.0)
    /// </summary>
    CKK_BLAKE2B_512_HMAC = 0x0000003D,

    /// <summary>
    /// Salsa20 stream cipher key (PKCS#11 v3.0)
    /// </summary>
    CKK_SALSA20 = 0x0000003E,

    /// <summary>
    /// Signal Double-Ratchet state key (PKCS#11 v3.0)
    /// </summary>
    CKK_X2RATCHET = 0x0000003F,

    /// <summary>
    /// Montgomery-curve key (X25519, X448) (PKCS#11 v3.0)
    /// </summary>
    CKK_EC_MONTGOMERY = 0x00000041,

    /// <summary>
    /// HKDF input keying material (PKCS#11 v3.0)
    /// </summary>
    CKK_HKDF = 0x00000042,

    /// <summary>
    /// SHA-512/224 HMAC key (PKCS#11 v3.0)
    /// </summary>
    CKK_SHA512_224_HMAC = 0x00000043,

    /// <summary>
    /// SHA-512/256 HMAC key (PKCS#11 v3.0)
    /// </summary>
    CKK_SHA512_256_HMAC = 0x00000044,

    /// <summary>
    /// Truncated SHA-512/T HMAC key (PKCS#11 v3.0)
    /// </summary>
    CKK_SHA512_T_HMAC = 0x00000045,

    /// <summary>
    /// HSS hash-based signature key per RFC 8554 (PKCS#11 v3.1)
    /// </summary>
    CKK_HSS = 0x00000046,

    /// <summary>
    /// ML-KEM (FIPS 203) key type — Kyber-derived (PKCS#11 v3.2)
    /// </summary>
    CKK_ML_KEM = 0x00000049,

    /// <summary>
    /// ML-DSA (FIPS 204) key type — Dilithium-derived (PKCS#11 v3.2)
    /// </summary>
    CKK_ML_DSA = 0x0000004A,

    /// <summary>
    /// SLH-DSA (FIPS 205) key type — SPHINCS+-derived (PKCS#11 v3.2)
    /// </summary>
    CKK_SLH_DSA = 0x0000004B,



    /// <summary>
    /// Permanently reserved for token vendors
    /// </summary>
    CKK_VENDOR_DEFINED = 0x80000000
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKKExtensions
{
    /// <summary>Converts <see cref="CKK"/> to <see cref="NativeCULong"/>.</summary>
    public static NativeCULong ToCULong(this CKK value)
    {
        return (NativeCULong)(ulong)value;
    }

    /// <summary>
    /// Fast loose cast from <see cref="NativeCULong"/> to <see cref="CKK"/>. Use only when the
    /// value is trusted; otherwise prefer <see cref="ToCKKChecked"/>.
    /// </summary>
    public static CKK ToCKK(this NativeCULong value)
    {
        return (CKK)(ulong)value;
    }

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKK"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// </summary>
    public static CKK ToCKKChecked(this NativeCULong value)
    {
        CKK result = (CKK)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKK), (ulong)value);
        return result;
    }
}