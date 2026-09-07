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
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve NistP192 { get; } = CreateFromValue(NistP192Oid, "nistP192");
        /// <summary>NIST P-224 / secp224r1.</summary>
        [Obsolete("P-224 provides ~112-bit security, below the 128-bit baseline (NIST legacy-approved through 2030 only). Use NistP256 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve NistP224 { get; } = CreateFromValue(NistP224Oid, "nistP224");
        /// <summary>NIST P-256 / secp256r1 / prime256v1. Recommended for most use cases.</summary>
        public static Pkcs11ECCurve NistP256 { get; } = CreateFromValue("1.2.840.10045.3.1.7", "nistP256");
        /// <summary>NIST P-384 / secp384r1.</summary>
        public static Pkcs11ECCurve NistP384 { get; } = CreateFromValue("1.3.132.0.34", "nistP384");
        /// <summary>NIST P-521 / secp521r1.</summary>
        public static Pkcs11ECCurve NistP521 { get; } = CreateFromValue("1.3.132.0.35", "nistP521");

        /// <summary>Koblitz curve secp192k1 (SEC 2).</summary>
        [Obsolete("secp192k1 provides ~96-bit security, below the 112-bit floor (NIST SP 800-57). Use Secp256k1 or NistP256 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve Secp192k1 { get; } = CreateFromValue(Secp192k1Oid, "secp192k1");
        /// <summary>Koblitz curve secp224k1 (SEC 2).</summary>
        [Obsolete("secp224k1 provides ~112-bit security, below the 128-bit baseline. Use Secp256k1 or NistP256 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve Secp224k1 { get; } = CreateFromValue(Secp224k1Oid, "secp224k1");
        /// <summary>Koblitz curve secp256k1 (SEC 2).</summary>
        public static Pkcs11ECCurve Secp256k1 { get; } = CreateFromValue("1.3.132.0.10", "secp256k1");

        // Brainpool curves (RFC 5639), 1.3.36.3.3.2.8.1.1.{1..14}.
        /// <summary>brainpoolP160r1.</summary>
        [Obsolete("brainpoolP160r1 provides ~80-bit security and is unsafe for modern use. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP160r1 { get; } = CreateFromValue(BrainpoolP160r1Oid, "brainpoolP160r1");
        /// <summary>brainpoolP160t1.</summary>
        [Obsolete("brainpoolP160t1 provides ~80-bit security and is unsafe for modern use. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP160t1 { get; } = CreateFromValue(BrainpoolP160t1Oid, "brainpoolP160t1");
        /// <summary>brainpoolP192r1.</summary>
        [Obsolete("brainpoolP192r1 provides ~96-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP192r1 { get; } = CreateFromValue(BrainpoolP192r1Oid, "brainpoolP192r1");
        /// <summary>brainpoolP192t1.</summary>
        [Obsolete("brainpoolP192t1 provides ~96-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP192t1 { get; } = CreateFromValue(BrainpoolP192t1Oid, "brainpoolP192t1");
        /// <summary>brainpoolP224r1.</summary>
        [Obsolete("brainpoolP224r1 provides ~112-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP224r1 { get; } = CreateFromValue(BrainpoolP224r1Oid, "brainpoolP224r1");
        /// <summary>brainpoolP224t1.</summary>
        [Obsolete("brainpoolP224t1 provides ~112-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP224t1 { get; } = CreateFromValue(BrainpoolP224t1Oid, "brainpoolP224t1");
        /// <summary>brainpoolP256r1.</summary>
        public static Pkcs11ECCurve BrainpoolP256r1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1");
        /// <summary>brainpoolP256t1.</summary>
        public static Pkcs11ECCurve BrainpoolP256t1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.8", "brainpoolP256t1");
        /// <summary>brainpoolP320r1.</summary>
        public static Pkcs11ECCurve BrainpoolP320r1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.9", "brainpoolP320r1");
        /// <summary>brainpoolP320t1.</summary>
        public static Pkcs11ECCurve BrainpoolP320t1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.10", "brainpoolP320t1");
        /// <summary>brainpoolP384r1.</summary>
        public static Pkcs11ECCurve BrainpoolP384r1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1");
        /// <summary>brainpoolP384t1.</summary>
        public static Pkcs11ECCurve BrainpoolP384t1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.12", "brainpoolP384t1");
        /// <summary>brainpoolP512r1.</summary>
        public static Pkcs11ECCurve BrainpoolP512r1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1");
        /// <summary>brainpoolP512t1.</summary>
        public static Pkcs11ECCurve BrainpoolP512t1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.14", "brainpoolP512t1");

        /// <summary>SM2 (GB/T 32918), OID 1.2.156.10197.1.301.</summary>
        public static Pkcs11ECCurve Sm2 { get; } = CreateFromValue("1.2.156.10197.1.301", "sm2");
    }

    // OID constants for the curves referenced from more than one table below (NamedCurves,
    // _namesByOid, _fieldSizeBitsByOid, and _belowBaselineOids) — avoids repeating the literal.
    private const string NistP192Oid = "1.2.840.10045.3.1.1";
    private const string NistP224Oid = "1.3.132.0.33";
    private const string Secp192k1Oid = "1.3.132.0.31";
    private const string Secp224k1Oid = "1.3.132.0.32";
    private const string BrainpoolP160r1Oid = "1.3.36.3.3.2.8.1.1.1";
    private const string BrainpoolP160t1Oid = "1.3.36.3.3.2.8.1.1.2";
    private const string BrainpoolP192r1Oid = "1.3.36.3.3.2.8.1.1.3";
    private const string BrainpoolP192t1Oid = "1.3.36.3.3.2.8.1.1.4";
    private const string BrainpoolP224r1Oid = "1.3.36.3.3.2.8.1.1.5";
    private const string BrainpoolP224t1Oid = "1.3.36.3.3.2.8.1.1.6";

    private static readonly Dictionary<string, string> _namesByOid = new(StringComparer.Ordinal)
    {
        [NistP192Oid] = "nistP192",
        [NistP224Oid] = "nistP224",
        ["1.2.840.10045.3.1.7"] = "nistP256",
        ["1.3.132.0.34"] = "nistP384",
        ["1.3.132.0.35"] = "nistP521",
        [Secp192k1Oid] = "secp192k1",
        [Secp224k1Oid] = "secp224k1",
        ["1.3.132.0.10"] = "secp256k1",
        [BrainpoolP160r1Oid] = "brainpoolP160r1",
        [BrainpoolP160t1Oid] = "brainpoolP160t1",
        [BrainpoolP192r1Oid] = "brainpoolP192r1",
        [BrainpoolP192t1Oid] = "brainpoolP192t1",
        [BrainpoolP224r1Oid] = "brainpoolP224r1",
        [BrainpoolP224t1Oid] = "brainpoolP224t1",
        ["1.3.36.3.3.2.8.1.1.7"] = "brainpoolP256r1",
        ["1.3.36.3.3.2.8.1.1.8"] = "brainpoolP256t1",
        ["1.3.36.3.3.2.8.1.1.9"] = "brainpoolP320r1",
        ["1.3.36.3.3.2.8.1.1.10"] = "brainpoolP320t1",
        ["1.3.36.3.3.2.8.1.1.11"] = "brainpoolP384r1",
        ["1.3.36.3.3.2.8.1.1.12"] = "brainpoolP384t1",
        ["1.3.36.3.3.2.8.1.1.13"] = "brainpoolP512r1",
        ["1.3.36.3.3.2.8.1.1.14"] = "brainpoolP512t1",
        ["1.2.156.10197.1.301"] = "sm2",
    };

    private static readonly Dictionary<string, string> _oidsByName =
        _namesByOid.ToDictionary(kv => kv.Value, kv => kv.Key, StringComparer.Ordinal);

    // Field size in bits per catalog curve. See FieldSizeBits.
    private static readonly Dictionary<string, int> _fieldSizeBitsByOid = new(StringComparer.Ordinal)
    {
        [NistP192Oid] = 192,             // nistP192
        [NistP224Oid] = 224,             // nistP224
        ["1.2.840.10045.3.1.7"] = 256,   // nistP256
        ["1.3.132.0.34"] = 384,          // nistP384
        ["1.3.132.0.35"] = 521,          // nistP521
        [Secp192k1Oid] = 192,            // secp192k1
        [Secp224k1Oid] = 224,            // secp224k1
        ["1.3.132.0.10"] = 256,          // secp256k1
        [BrainpoolP160r1Oid] = 160,      // brainpoolP160r1
        [BrainpoolP160t1Oid] = 160,      // brainpoolP160t1
        [BrainpoolP192r1Oid] = 192,      // brainpoolP192r1
        [BrainpoolP192t1Oid] = 192,      // brainpoolP192t1
        [BrainpoolP224r1Oid] = 224,      // brainpoolP224r1
        [BrainpoolP224t1Oid] = 224,      // brainpoolP224t1
        ["1.3.36.3.3.2.8.1.1.7"] = 256,  // brainpoolP256r1
        ["1.3.36.3.3.2.8.1.1.8"] = 256,  // brainpoolP256t1
        ["1.3.36.3.3.2.8.1.1.9"] = 320,  // brainpoolP320r1
        ["1.3.36.3.3.2.8.1.1.10"] = 320, // brainpoolP320t1
        ["1.3.36.3.3.2.8.1.1.11"] = 384, // brainpoolP384r1
        ["1.3.36.3.3.2.8.1.1.12"] = 384, // brainpoolP384t1
        ["1.3.36.3.3.2.8.1.1.13"] = 512, // brainpoolP512r1
        ["1.3.36.3.3.2.8.1.1.14"] = 512, // brainpoolP512t1
        ["1.2.156.10197.1.301"] = 256,   // sm2
    };

    // Catalog curves providing < 128-bit security (field size < 256-bit): the 160/192/224-bit NIST
    // and Brainpool curves. GenerateEcKeyPair gates these behind AllowInsecure. See IsBelowSecurityBaseline.
    private static readonly HashSet<string> _belowBaselineOids = new(StringComparer.Ordinal)
    {
        NistP192Oid,          // nistP192        ~96-bit
        NistP224Oid,          // nistP224        ~112-bit
        Secp192k1Oid,         // secp192k1       ~96-bit
        Secp224k1Oid,         // secp224k1       ~112-bit
        BrainpoolP160r1Oid,   // brainpoolP160r1 ~80-bit
        BrainpoolP160t1Oid,   // brainpoolP160t1 ~80-bit
        BrainpoolP192r1Oid,   // brainpoolP192r1 ~96-bit
        BrainpoolP192t1Oid,   // brainpoolP192t1 ~96-bit
        BrainpoolP224r1Oid,   // brainpoolP224r1 ~112-bit
        BrainpoolP224t1Oid,   // brainpoolP224t1 ~112-bit
    };
}
