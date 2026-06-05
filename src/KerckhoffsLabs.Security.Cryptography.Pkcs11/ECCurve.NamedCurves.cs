using System.Linq;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

public readonly partial struct ECCurve
{
    /// <summary>
    /// Named prime-field (Weierstrass) curves a PKCS#11 v3.2 token may support via
    /// <c>CKM_EC_KEY_PAIR_GEN</c>. Mirrors the BCL <c>ECCurve.NamedCurves</c> and extends it with the
    /// curves PKCS#11 tokens additionally implement (NIST P-192/P-224, secp256k1, SM2).
    /// </summary>
    public static class NamedCurves
    {
        // NIST / SECG prime curves (FIPS 186-4 / SEC 2).
        /// <summary>NIST P-192 / secp192r1 / prime192v1.</summary>
        [Obsolete("P-192 provides ~96-bit security, below the 112-bit floor (NIST SP 800-57) and removed from FIPS 186-5. Use NistP256 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.")]
        public static ECCurve NistP192 { get; } = CreateFromValue("1.2.840.10045.3.1.1", "nistP192");
        /// <summary>NIST P-224 / secp224r1.</summary>
        [Obsolete("P-224 provides ~112-bit security, below the 128-bit baseline (NIST legacy-approved through 2030 only). Use NistP256 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.")]
        public static ECCurve NistP224 { get; } = CreateFromValue("1.3.132.0.33", "nistP224");
        /// <summary>NIST P-256 / secp256r1 / prime256v1. Recommended for most use cases.</summary>
        public static ECCurve NistP256 { get; } = CreateFromValue("1.2.840.10045.3.1.7", "nistP256");
        /// <summary>NIST P-384 / secp384r1.</summary>
        public static ECCurve NistP384 { get; } = CreateFromValue("1.3.132.0.34", "nistP384");
        /// <summary>NIST P-521 / secp521r1.</summary>
        public static ECCurve NistP521 { get; } = CreateFromValue("1.3.132.0.35", "nistP521");

        /// <summary>Koblitz curve secp192k1 (SEC 2).</summary>
        [Obsolete("secp192k1 provides ~96-bit security, below the 112-bit floor (NIST SP 800-57). Use Secp256k1 or NistP256 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.")]
        public static ECCurve Secp192k1 { get; } = CreateFromValue("1.3.132.0.31", "secp192k1");
        /// <summary>Koblitz curve secp224k1 (SEC 2).</summary>
        [Obsolete("secp224k1 provides ~112-bit security, below the 128-bit baseline. Use Secp256k1 or NistP256 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.")]
        public static ECCurve Secp224k1 { get; } = CreateFromValue("1.3.132.0.32", "secp224k1");
        /// <summary>Koblitz curve secp256k1 (SEC 2).</summary>
        public static ECCurve Secp256k1 { get; } = CreateFromValue("1.3.132.0.10", "secp256k1");

        // Brainpool curves (RFC 5639), 1.3.36.3.3.2.8.1.1.{1..14}.
        /// <summary>brainpoolP160r1.</summary>
        [Obsolete("brainpoolP160r1 provides ~80-bit security and is unsafe for modern use. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.")]
        public static ECCurve BrainpoolP160r1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.1", "brainpoolP160r1");
        /// <summary>brainpoolP160t1.</summary>
        [Obsolete("brainpoolP160t1 provides ~80-bit security and is unsafe for modern use. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.")]
        public static ECCurve BrainpoolP160t1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.2", "brainpoolP160t1");
        /// <summary>brainpoolP192r1.</summary>
        [Obsolete("brainpoolP192r1 provides ~96-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.")]
        public static ECCurve BrainpoolP192r1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.3", "brainpoolP192r1");
        /// <summary>brainpoolP192t1.</summary>
        [Obsolete("brainpoolP192t1 provides ~96-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.")]
        public static ECCurve BrainpoolP192t1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.4", "brainpoolP192t1");
        /// <summary>brainpoolP224r1.</summary>
        [Obsolete("brainpoolP224r1 provides ~112-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.")]
        public static ECCurve BrainpoolP224r1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.5", "brainpoolP224r1");
        /// <summary>brainpoolP224t1.</summary>
        [Obsolete("brainpoolP224t1 provides ~112-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Workspace.GenerateEcKeyPair throws InsecureOperationException unless Pkcs11Workspace.AllowInsecure = true.")]
        public static ECCurve BrainpoolP224t1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.6", "brainpoolP224t1");
        /// <summary>brainpoolP256r1.</summary>
        public static ECCurve BrainpoolP256r1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1");
        /// <summary>brainpoolP256t1.</summary>
        public static ECCurve BrainpoolP256t1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.8", "brainpoolP256t1");
        /// <summary>brainpoolP320r1.</summary>
        public static ECCurve BrainpoolP320r1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.9", "brainpoolP320r1");
        /// <summary>brainpoolP320t1.</summary>
        public static ECCurve BrainpoolP320t1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.10", "brainpoolP320t1");
        /// <summary>brainpoolP384r1.</summary>
        public static ECCurve BrainpoolP384r1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1");
        /// <summary>brainpoolP384t1.</summary>
        public static ECCurve BrainpoolP384t1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.12", "brainpoolP384t1");
        /// <summary>brainpoolP512r1.</summary>
        public static ECCurve BrainpoolP512r1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1");
        /// <summary>brainpoolP512t1.</summary>
        public static ECCurve BrainpoolP512t1 { get; } = CreateFromValue("1.3.36.3.3.2.8.1.1.14", "brainpoolP512t1");

        /// <summary>SM2 (GB/T 32918), OID 1.2.156.10197.1.301.</summary>
        public static ECCurve Sm2 { get; } = CreateFromValue("1.2.156.10197.1.301", "sm2");
    }

    private static readonly Dictionary<string, string> s_namesByOid = new(StringComparer.Ordinal)
    {
        ["1.2.840.10045.3.1.1"] = "nistP192",
        ["1.3.132.0.33"] = "nistP224",
        ["1.2.840.10045.3.1.7"] = "nistP256",
        ["1.3.132.0.34"] = "nistP384",
        ["1.3.132.0.35"] = "nistP521",
        ["1.3.132.0.31"] = "secp192k1",
        ["1.3.132.0.32"] = "secp224k1",
        ["1.3.132.0.10"] = "secp256k1",
        ["1.3.36.3.3.2.8.1.1.1"] = "brainpoolP160r1",
        ["1.3.36.3.3.2.8.1.1.2"] = "brainpoolP160t1",
        ["1.3.36.3.3.2.8.1.1.3"] = "brainpoolP192r1",
        ["1.3.36.3.3.2.8.1.1.4"] = "brainpoolP192t1",
        ["1.3.36.3.3.2.8.1.1.5"] = "brainpoolP224r1",
        ["1.3.36.3.3.2.8.1.1.6"] = "brainpoolP224t1",
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

    private static readonly Dictionary<string, string> s_oidsByName =
        s_namesByOid.ToDictionary(kv => kv.Value, kv => kv.Key, StringComparer.Ordinal);

    // Catalog curves providing < 128-bit security (field size < 256-bit): the 160/192/224-bit NIST
    // and Brainpool curves. GenerateEcKeyPair gates these behind AllowInsecure. See IsBelowSecurityBaseline.
    private static readonly HashSet<string> s_belowBaselineOids = new(StringComparer.Ordinal)
    {
        "1.2.840.10045.3.1.1",   // nistP192        ~96-bit
        "1.3.132.0.33",          // nistP224        ~112-bit
        "1.3.132.0.31",          // secp192k1       ~96-bit
        "1.3.132.0.32",          // secp224k1       ~112-bit
        "1.3.36.3.3.2.8.1.1.1",  // brainpoolP160r1 ~80-bit
        "1.3.36.3.3.2.8.1.1.2",  // brainpoolP160t1 ~80-bit
        "1.3.36.3.3.2.8.1.1.3",  // brainpoolP192r1 ~96-bit
        "1.3.36.3.3.2.8.1.1.4",  // brainpoolP192t1 ~96-bit
        "1.3.36.3.3.2.8.1.1.5",  // brainpoolP224r1 ~112-bit
        "1.3.36.3.3.2.8.1.1.6",  // brainpoolP224t1 ~112-bit
    };
}
