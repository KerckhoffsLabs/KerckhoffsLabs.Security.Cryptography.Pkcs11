namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Every object identifier the library uses, in one place, each with the standard that assigns it. No
/// other source file spells out an OID (<c>OidLiteralTests</c> enforces it); tests that check these
/// values against their standards write the literals out on their own.
/// </summary>
internal static class Oids
{
    /// <summary>
    /// <c>AlgorithmIdentifier</c> OIDs of a <c>SubjectPublicKeyInfo</c>: the algorithm a public key is for.
    /// </summary>
    internal static class KeyAlgorithms
    {
        /// <summary><c>rsaEncryption</c> (RFC 8017 §A.1, RFC 3279 §2.3.1).</summary>
        internal const string RsaEncryption = "1.2.840.113549.1.1.1";

        /// <summary><c>id-RSASSA-PSS</c> (RFC 8017 §A.2.3, RFC 4055 §3.1).</summary>
        internal const string RsaSsaPss = "1.2.840.113549.1.1.10";

        /// <summary><c>id-ecPublicKey</c> (RFC 5480 §2.1.1).</summary>
        internal const string EcPublicKey = "1.2.840.10045.2.1";

        /// <summary><c>id-dsa</c> (RFC 3279 §2.3.2).</summary>
        internal const string Dsa = "1.2.840.10040.4.1";
    }

    /// <summary>
    /// <i>namedCurve</i> OIDs: the <c>CKA_EC_PARAMS</c> value of a key on the curve, and the parameters of an
    /// <c>id-ecPublicKey</c> <c>SubjectPublicKeyInfo</c>.
    /// </summary>
    internal static class Curves
    {
        // NIST / SECG prime curves (FIPS 186-4, SEC 2 v2, RFC 5480 §2.1.1.1).
        internal const string NistP192 = "1.2.840.10045.3.1.1";
        internal const string NistP224 = "1.3.132.0.33";
        internal const string NistP256 = "1.2.840.10045.3.1.7";
        internal const string NistP384 = "1.3.132.0.34";
        internal const string NistP521 = "1.3.132.0.35";

        // SECG Koblitz curves (SEC 2 v2).
        internal const string Secp192k1 = "1.3.132.0.31";
        internal const string Secp224k1 = "1.3.132.0.32";
        internal const string Secp256k1 = "1.3.132.0.10";

        // Brainpool (RFC 5639 §4.1).
        internal const string BrainpoolP160r1 = "1.3.36.3.3.2.8.1.1.1";
        internal const string BrainpoolP160t1 = "1.3.36.3.3.2.8.1.1.2";
        internal const string BrainpoolP192r1 = "1.3.36.3.3.2.8.1.1.3";
        internal const string BrainpoolP192t1 = "1.3.36.3.3.2.8.1.1.4";
        internal const string BrainpoolP224r1 = "1.3.36.3.3.2.8.1.1.5";
        internal const string BrainpoolP224t1 = "1.3.36.3.3.2.8.1.1.6";
        internal const string BrainpoolP256r1 = "1.3.36.3.3.2.8.1.1.7";
        internal const string BrainpoolP256t1 = "1.3.36.3.3.2.8.1.1.8";
        internal const string BrainpoolP320r1 = "1.3.36.3.3.2.8.1.1.9";
        internal const string BrainpoolP320t1 = "1.3.36.3.3.2.8.1.1.10";
        internal const string BrainpoolP384r1 = "1.3.36.3.3.2.8.1.1.11";
        internal const string BrainpoolP384t1 = "1.3.36.3.3.2.8.1.1.12";
        internal const string BrainpoolP512r1 = "1.3.36.3.3.2.8.1.1.13";
        internal const string BrainpoolP512t1 = "1.3.36.3.3.2.8.1.1.14";

        // SM2 (GB/T 32918.5, GM/T 0006).
        internal const string Sm2 = "1.2.156.10197.1.301";
    }
}
