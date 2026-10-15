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
        public static Pkcs11ECCurve NistP192 { get; } = CreateFromValue(NistP192Oid);
        /// <summary>NIST P-224 / secp224r1.</summary>
        [Obsolete("P-224 provides ~112-bit security, below the 128-bit baseline (NIST legacy-approved through 2030 only). Use NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve NistP224 { get; } = CreateFromValue(NistP224Oid);
        /// <summary>NIST P-256 / secp256r1 / prime256v1. Recommended for most use cases.</summary>
        public static Pkcs11ECCurve NistP256 { get; } = CreateFromValue(NistP256Oid);
        /// <summary>NIST P-384 / secp384r1.</summary>
        public static Pkcs11ECCurve NistP384 { get; } = CreateFromValue(NistP384Oid);
        /// <summary>NIST P-521 / secp521r1.</summary>
        public static Pkcs11ECCurve NistP521 { get; } = CreateFromValue(NistP521Oid);

        /// <summary>Koblitz curve secp192k1 (SEC 2).</summary>
        [Obsolete("secp192k1 provides ~96-bit security, below the 112-bit floor (NIST SP 800-57). Use Secp256k1 or NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve Secp192k1 { get; } = CreateFromValue(Secp192k1Oid);
        /// <summary>Koblitz curve secp224k1 (SEC 2).</summary>
        [Obsolete("secp224k1 provides ~112-bit security, below the 128-bit baseline. Use Secp256k1 or NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve Secp224k1 { get; } = CreateFromValue(Secp224k1Oid);
        /// <summary>Koblitz curve secp256k1 (SEC 2).</summary>
        public static Pkcs11ECCurve Secp256k1 { get; } = CreateFromValue(Secp256k1Oid);

        // Brainpool curves (RFC 5639), 1.3.36.3.3.2.8.1.1.{1..14}.
        /// <summary>brainpoolP160r1.</summary>
        [Obsolete("brainpoolP160r1 provides ~80-bit security and is unsafe for modern use. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP160r1 { get; } = CreateFromValue(BrainpoolP160r1Oid);
        /// <summary>brainpoolP160t1.</summary>
        [Obsolete("brainpoolP160t1 provides ~80-bit security and is unsafe for modern use. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP160t1 { get; } = CreateFromValue(BrainpoolP160t1Oid);
        /// <summary>brainpoolP192r1.</summary>
        [Obsolete("brainpoolP192r1 provides ~96-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP192r1 { get; } = CreateFromValue(BrainpoolP192r1Oid);
        /// <summary>brainpoolP192t1.</summary>
        [Obsolete("brainpoolP192t1 provides ~96-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP192t1 { get; } = CreateFromValue(BrainpoolP192t1Oid);
        /// <summary>brainpoolP224r1.</summary>
        [Obsolete("brainpoolP224r1 provides ~112-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP224r1 { get; } = CreateFromValue(BrainpoolP224r1Oid);
        /// <summary>brainpoolP224t1.</summary>
        [Obsolete("brainpoolP224t1 provides ~112-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP224t1 { get; } = CreateFromValue(BrainpoolP224t1Oid);
        /// <summary>brainpoolP256r1.</summary>
        public static Pkcs11ECCurve BrainpoolP256r1 { get; } = CreateFromValue(BrainpoolP256r1Oid);
        /// <summary>brainpoolP256t1.</summary>
        public static Pkcs11ECCurve BrainpoolP256t1 { get; } = CreateFromValue(BrainpoolP256t1Oid);
        /// <summary>brainpoolP320r1.</summary>
        public static Pkcs11ECCurve BrainpoolP320r1 { get; } = CreateFromValue(BrainpoolP320r1Oid);
        /// <summary>brainpoolP320t1.</summary>
        public static Pkcs11ECCurve BrainpoolP320t1 { get; } = CreateFromValue(BrainpoolP320t1Oid);
        /// <summary>brainpoolP384r1.</summary>
        public static Pkcs11ECCurve BrainpoolP384r1 { get; } = CreateFromValue(BrainpoolP384r1Oid);
        /// <summary>brainpoolP384t1.</summary>
        public static Pkcs11ECCurve BrainpoolP384t1 { get; } = CreateFromValue(BrainpoolP384t1Oid);
        /// <summary>brainpoolP512r1.</summary>
        public static Pkcs11ECCurve BrainpoolP512r1 { get; } = CreateFromValue(BrainpoolP512r1Oid);
        /// <summary>brainpoolP512t1.</summary>
        public static Pkcs11ECCurve BrainpoolP512t1 { get; } = CreateFromValue(BrainpoolP512t1Oid);

        /// <summary>SM2 (GB/T 32918), OID 1.2.156.10197.1.301.</summary>
        public static Pkcs11ECCurve Sm2 { get; } = CreateFromValue(Sm2Oid);
    }

    // OID constants for every catalog curve, referenced from NamedCurves and from _catalog.
    private const string NistP192Oid = "1.2.840.10045.3.1.1";
    private const string NistP224Oid = "1.3.132.0.33";
    private const string NistP256Oid = "1.2.840.10045.3.1.7";
    private const string NistP384Oid = "1.3.132.0.34";
    private const string NistP521Oid = "1.3.132.0.35";
    private const string Secp192k1Oid = "1.3.132.0.31";
    private const string Secp224k1Oid = "1.3.132.0.32";
    private const string Secp256k1Oid = "1.3.132.0.10";
    private const string BrainpoolP160r1Oid = "1.3.36.3.3.2.8.1.1.1";
    private const string BrainpoolP160t1Oid = "1.3.36.3.3.2.8.1.1.2";
    private const string BrainpoolP192r1Oid = "1.3.36.3.3.2.8.1.1.3";
    private const string BrainpoolP192t1Oid = "1.3.36.3.3.2.8.1.1.4";
    private const string BrainpoolP224r1Oid = "1.3.36.3.3.2.8.1.1.5";
    private const string BrainpoolP224t1Oid = "1.3.36.3.3.2.8.1.1.6";
    private const string BrainpoolP256r1Oid = "1.3.36.3.3.2.8.1.1.7";
    private const string BrainpoolP256t1Oid = "1.3.36.3.3.2.8.1.1.8";
    private const string BrainpoolP320r1Oid = "1.3.36.3.3.2.8.1.1.9";
    private const string BrainpoolP320t1Oid = "1.3.36.3.3.2.8.1.1.10";
    private const string BrainpoolP384r1Oid = "1.3.36.3.3.2.8.1.1.11";
    private const string BrainpoolP384t1Oid = "1.3.36.3.3.2.8.1.1.12";
    private const string BrainpoolP512r1Oid = "1.3.36.3.3.2.8.1.1.13";
    private const string BrainpoolP512t1Oid = "1.3.36.3.3.2.8.1.1.14";
    private const string Sm2Oid = "1.2.156.10197.1.301";

    // The curve catalog: one row per curve, with its BCL-style friendly name and its field size in bits
    // (see FieldSizeBits). Every lookup below is derived from it, so adding a curve is one row here,
    // plus a NamedCurves property for a shortcut.
    private static readonly (string Oid, string Name, int FieldSizeBits)[] _catalog =
    [
        (NistP192Oid,        "nistP192",        192),
        (NistP224Oid,        "nistP224",        224),
        (NistP256Oid,        "nistP256",        256),
        (NistP384Oid,        "nistP384",        384),
        (NistP521Oid,        "nistP521",        521),
        (Secp192k1Oid,       "secp192k1",       192),
        (Secp224k1Oid,       "secp224k1",       224),
        (Secp256k1Oid,       "secp256k1",       256),
        (BrainpoolP160r1Oid, "brainpoolP160r1", 160),
        (BrainpoolP160t1Oid, "brainpoolP160t1", 160),
        (BrainpoolP192r1Oid, "brainpoolP192r1", 192),
        (BrainpoolP192t1Oid, "brainpoolP192t1", 192),
        (BrainpoolP224r1Oid, "brainpoolP224r1", 224),
        (BrainpoolP224t1Oid, "brainpoolP224t1", 224),
        (BrainpoolP256r1Oid, "brainpoolP256r1", 256),
        (BrainpoolP256t1Oid, "brainpoolP256t1", 256),
        (BrainpoolP320r1Oid, "brainpoolP320r1", 320),
        (BrainpoolP320t1Oid, "brainpoolP320t1", 320),
        (BrainpoolP384r1Oid, "brainpoolP384r1", 384),
        (BrainpoolP384t1Oid, "brainpoolP384t1", 384),
        (BrainpoolP512r1Oid, "brainpoolP512r1", 512),
        (BrainpoolP512t1Oid, "brainpoolP512t1", 512),
        (Sm2Oid,             "sm2",             256),
    ];

    private static readonly Dictionary<string, string> _namesByOid =
        _catalog.ToDictionary(c => c.Oid, c => c.Name, StringComparer.Ordinal);

    private static readonly Dictionary<string, string> _oidsByName =
        _catalog.ToDictionary(c => c.Name, c => c.Oid, StringComparer.Ordinal);

    private static readonly Dictionary<string, int> _fieldSizeBitsByOid =
        _catalog.ToDictionary(c => c.Oid, c => c.FieldSizeBits, StringComparer.Ordinal);
}
