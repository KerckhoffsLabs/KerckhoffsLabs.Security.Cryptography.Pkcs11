using System.Collections.Frozen;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

public readonly partial struct Pkcs11ECCurve
{
    /// <summary>
    /// Named prime-field (Weierstrass) curves a PKCS#11 v3.2 token may support via
    /// <c>CKM_EC_KEY_PAIR_GEN</c>. Mirrors the BCL <c>Pkcs11ECCurve.NamedCurves</c> and extends it with the
    /// curves PKCS#11 tokens additionally implement (NIST P-192/P-224, secp256k1, SM2).
    /// </summary>
    public static class NamedCurves
    {
        // NIST / SECG prime curves (FIPS 186-4 / SEC 2).
        /// <summary>NIST P-192 / secp192r1 / prime192v1.</summary>
        [Obsolete("P-192 provides ~96-bit security, below the 112-bit floor (NIST SP 800-57) and removed from FIPS 186-5. Use NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve NistP192 => Get(NistP192Oid);
        /// <summary>NIST P-224 / secp224r1.</summary>
        [Obsolete("P-224 provides ~112-bit security, below the 128-bit baseline (NIST legacy-approved through 2030 only). Use NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve NistP224 => Get(NistP224Oid);
        /// <summary>NIST P-256 / secp256r1 / prime256v1. Recommended for most use cases.</summary>
        public static Pkcs11ECCurve NistP256 => Get(NistP256Oid);
        /// <summary>NIST P-384 / secp384r1.</summary>
        public static Pkcs11ECCurve NistP384 => Get(NistP384Oid);
        /// <summary>NIST P-521 / secp521r1.</summary>
        public static Pkcs11ECCurve NistP521 => Get(NistP521Oid);

        /// <summary>Koblitz curve secp192k1 (SEC 2).</summary>
        [Obsolete("secp192k1 provides ~96-bit security, below the 112-bit floor (NIST SP 800-57). Use Secp256k1 or NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve Secp192k1 => Get(Secp192k1Oid);
        /// <summary>Koblitz curve secp224k1 (SEC 2).</summary>
        [Obsolete("secp224k1 provides ~112-bit security, below the 128-bit baseline. Use Secp256k1 or NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve Secp224k1 => Get(Secp224k1Oid);
        /// <summary>Koblitz curve secp256k1 (SEC 2).</summary>
        public static Pkcs11ECCurve Secp256k1 => Get(Secp256k1Oid);

        // Brainpool curves (RFC 5639), 1.3.36.3.3.2.8.1.1.{1..14}.
        /// <summary>brainpoolP160r1.</summary>
        [Obsolete("brainpoolP160r1 provides ~80-bit security and is unsafe for modern use. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP160r1 => Get(BrainpoolP160r1Oid);
        /// <summary>brainpoolP160t1.</summary>
        [Obsolete("brainpoolP160t1 provides ~80-bit security and is unsafe for modern use. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP160t1 => Get(BrainpoolP160t1Oid);
        /// <summary>brainpoolP192r1.</summary>
        [Obsolete("brainpoolP192r1 provides ~96-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP192r1 => Get(BrainpoolP192r1Oid);
        /// <summary>brainpoolP192t1.</summary>
        [Obsolete("brainpoolP192t1 provides ~96-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP192t1 => Get(BrainpoolP192t1Oid);
        /// <summary>brainpoolP224r1.</summary>
        [Obsolete("brainpoolP224r1 provides ~112-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP224r1 => Get(BrainpoolP224r1Oid);
        /// <summary>brainpoolP224t1.</summary>
        [Obsolete("brainpoolP224t1 provides ~112-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP224t1 => Get(BrainpoolP224t1Oid);
        /// <summary>brainpoolP256r1.</summary>
        public static Pkcs11ECCurve BrainpoolP256r1 => Get(BrainpoolP256r1Oid);
        /// <summary>brainpoolP256t1.</summary>
        public static Pkcs11ECCurve BrainpoolP256t1 => Get(BrainpoolP256t1Oid);
        /// <summary>brainpoolP320r1.</summary>
        public static Pkcs11ECCurve BrainpoolP320r1 => Get(BrainpoolP320r1Oid);
        /// <summary>brainpoolP320t1.</summary>
        public static Pkcs11ECCurve BrainpoolP320t1 => Get(BrainpoolP320t1Oid);
        /// <summary>brainpoolP384r1.</summary>
        public static Pkcs11ECCurve BrainpoolP384r1 => Get(BrainpoolP384r1Oid);
        /// <summary>brainpoolP384t1.</summary>
        public static Pkcs11ECCurve BrainpoolP384t1 => Get(BrainpoolP384t1Oid);
        /// <summary>brainpoolP512r1.</summary>
        public static Pkcs11ECCurve BrainpoolP512r1 => Get(BrainpoolP512r1Oid);
        /// <summary>brainpoolP512t1.</summary>
        public static Pkcs11ECCurve BrainpoolP512t1 => Get(BrainpoolP512t1Oid);

        /// <summary>SM2 (GB/T 32918), OID 1.2.156.10197.1.301.</summary>
        public static Pkcs11ECCurve Sm2 => Get(Sm2Oid);

        // Every built-in curve, built once from Pkcs11CurveCatalog.Default so the names and field sizes
        // have one source. The properties read from here rather than being auto-properties: coverage
        // tools don't report an auto-property's compiler-generated getter or the static constructor its
        // initializer runs in, which left this whole class unmeasured.
        private static readonly FrozenDictionary<string, Pkcs11ECCurve> BuiltIn =
            Pkcs11CurveCatalog.Default.Curves.ToFrozenDictionary(c => c.Oid, FromInfo, StringComparer.Ordinal);

        private static Pkcs11ECCurve Get(string oid) => BuiltIn[oid];
    }

    // OID constants for every built-in curve, referenced from NamedCurves and from Pkcs11CurveCatalog.Default.
    internal const string NistP192Oid = "1.2.840.10045.3.1.1";
    internal const string NistP224Oid = "1.3.132.0.33";
    internal const string NistP256Oid = "1.2.840.10045.3.1.7";
    internal const string NistP384Oid = "1.3.132.0.34";
    internal const string NistP521Oid = "1.3.132.0.35";
    internal const string Secp192k1Oid = "1.3.132.0.31";
    internal const string Secp224k1Oid = "1.3.132.0.32";
    internal const string Secp256k1Oid = "1.3.132.0.10";
    internal const string BrainpoolP160r1Oid = "1.3.36.3.3.2.8.1.1.1";
    internal const string BrainpoolP160t1Oid = "1.3.36.3.3.2.8.1.1.2";
    internal const string BrainpoolP192r1Oid = "1.3.36.3.3.2.8.1.1.3";
    internal const string BrainpoolP192t1Oid = "1.3.36.3.3.2.8.1.1.4";
    internal const string BrainpoolP224r1Oid = "1.3.36.3.3.2.8.1.1.5";
    internal const string BrainpoolP224t1Oid = "1.3.36.3.3.2.8.1.1.6";
    internal const string BrainpoolP256r1Oid = "1.3.36.3.3.2.8.1.1.7";
    internal const string BrainpoolP256t1Oid = "1.3.36.3.3.2.8.1.1.8";
    internal const string BrainpoolP320r1Oid = "1.3.36.3.3.2.8.1.1.9";
    internal const string BrainpoolP320t1Oid = "1.3.36.3.3.2.8.1.1.10";
    internal const string BrainpoolP384r1Oid = "1.3.36.3.3.2.8.1.1.11";
    internal const string BrainpoolP384t1Oid = "1.3.36.3.3.2.8.1.1.12";
    internal const string BrainpoolP512r1Oid = "1.3.36.3.3.2.8.1.1.13";
    internal const string BrainpoolP512t1Oid = "1.3.36.3.3.2.8.1.1.14";
    internal const string Sm2Oid = "1.2.156.10197.1.301";
}
