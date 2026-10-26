using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

public readonly partial struct Pkcs11ECCurve
{
    /// <summary>
    /// Named prime-field (Weierstrass) curves a PKCS#11 v3.2 token may support via
    /// <c>CKM_EC_KEY_PAIR_GEN</c>. Mirrors the BCL <c>Pkcs11ECCurve.NamedCurves</c> and extends it with the
    /// curves PKCS#11 tokens additionally implement (NIST P-192/P-224, the SEC 2 160-bit curves, secp256k1, SM2).
    /// </summary>
    public static class NamedCurves
    {
        // NIST / SECG prime curves (FIPS 186-4 / SEC 2).
        /// <summary>NIST P-192 / secp192r1 / prime192v1.</summary>
        [Obsolete("P-192 provides ~96-bit security, below the 112-bit floor (NIST SP 800-57) and removed from FIPS 186-5. Use NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve NistP192 => Get(Oids.Curves.NistP192);
        /// <summary>NIST P-224 / secp224r1.</summary>
        [Obsolete("P-224 provides ~112-bit security, below the 128-bit baseline (NIST legacy-approved through 2030 only). Use NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve NistP224 => Get(Oids.Curves.NistP224);
        /// <summary>NIST P-256 / secp256r1 / prime256v1. Recommended for most use cases.</summary>
        public static Pkcs11ECCurve NistP256 => Get(Oids.Curves.NistP256);
        /// <summary>NIST P-384 / secp384r1.</summary>
        public static Pkcs11ECCurve NistP384 => Get(Oids.Curves.NistP384);
        /// <summary>NIST P-521 / secp521r1.</summary>
        public static Pkcs11ECCurve NistP521 => Get(Oids.Curves.NistP521);

        /// <summary>Koblitz curve secp160k1 (SEC 2).</summary>
        [Obsolete("secp160k1 provides ~80-bit security and is unsafe for modern use. Use Secp256k1 or NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve Secp160k1 => Get(Oids.Curves.Secp160k1);
        /// <summary>Prime curve secp160r1 (SEC 2).</summary>
        [Obsolete("secp160r1 provides ~80-bit security and is unsafe for modern use. Use Secp256k1 or NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve Secp160r1 => Get(Oids.Curves.Secp160r1);
        /// <summary>Prime curve secp160r2 (SEC 2).</summary>
        [Obsolete("secp160r2 provides ~80-bit security and is unsafe for modern use. Use Secp256k1 or NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve Secp160r2 => Get(Oids.Curves.Secp160r2);
        /// <summary>Koblitz curve secp192k1 (SEC 2).</summary>
        [Obsolete("secp192k1 provides ~96-bit security, below the 112-bit floor (NIST SP 800-57). Use Secp256k1 or NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve Secp192k1 => Get(Oids.Curves.Secp192k1);
        /// <summary>Koblitz curve secp224k1 (SEC 2).</summary>
        [Obsolete("secp224k1 provides ~112-bit security, below the 128-bit baseline. Use Secp256k1 or NistP256 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve Secp224k1 => Get(Oids.Curves.Secp224k1);
        /// <summary>Koblitz curve secp256k1 (SEC 2).</summary>
        public static Pkcs11ECCurve Secp256k1 => Get(Oids.Curves.Secp256k1);

        // Brainpool curves (RFC 5639), 1.3.36.3.3.2.8.1.1.{1..14}.
        /// <summary>brainpoolP160r1.</summary>
        [Obsolete("brainpoolP160r1 provides ~80-bit security and is unsafe for modern use. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP160r1 => Get(Oids.Curves.BrainpoolP160r1);
        /// <summary>brainpoolP160t1.</summary>
        [Obsolete("brainpoolP160t1 provides ~80-bit security and is unsafe for modern use. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP160t1 => Get(Oids.Curves.BrainpoolP160t1);
        /// <summary>brainpoolP192r1.</summary>
        [Obsolete("brainpoolP192r1 provides ~96-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP192r1 => Get(Oids.Curves.BrainpoolP192r1);
        /// <summary>brainpoolP192t1.</summary>
        [Obsolete("brainpoolP192t1 provides ~96-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP192t1 => Get(Oids.Curves.BrainpoolP192t1);
        /// <summary>brainpoolP224r1.</summary>
        [Obsolete("brainpoolP224r1 provides ~112-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP224r1 => Get(Oids.Curves.BrainpoolP224r1);
        /// <summary>brainpoolP224t1.</summary>
        [Obsolete("brainpoolP224t1 provides ~112-bit security, below the 128-bit baseline. Use BrainpoolP256r1 or stronger. " +
                  "Pkcs11Session.GenerateEcKeyPair throws CryptoPolicyViolationException unless a policy that permits it (e.g. Pkcs11Session.UsePolicy(CryptoPolicy.AllowInsecure)) is in effect.",
            DiagnosticId = DiagnosticIds.WeakEcCurve,
            UrlFormat = DiagnosticIds.UrlFormat)]
        public static Pkcs11ECCurve BrainpoolP224t1 => Get(Oids.Curves.BrainpoolP224t1);
        /// <summary>brainpoolP256r1.</summary>
        public static Pkcs11ECCurve BrainpoolP256r1 => Get(Oids.Curves.BrainpoolP256r1);
        /// <summary>brainpoolP256t1.</summary>
        public static Pkcs11ECCurve BrainpoolP256t1 => Get(Oids.Curves.BrainpoolP256t1);
        /// <summary>brainpoolP320r1.</summary>
        public static Pkcs11ECCurve BrainpoolP320r1 => Get(Oids.Curves.BrainpoolP320r1);
        /// <summary>brainpoolP320t1.</summary>
        public static Pkcs11ECCurve BrainpoolP320t1 => Get(Oids.Curves.BrainpoolP320t1);
        /// <summary>brainpoolP384r1.</summary>
        public static Pkcs11ECCurve BrainpoolP384r1 => Get(Oids.Curves.BrainpoolP384r1);
        /// <summary>brainpoolP384t1.</summary>
        public static Pkcs11ECCurve BrainpoolP384t1 => Get(Oids.Curves.BrainpoolP384t1);
        /// <summary>brainpoolP512r1.</summary>
        public static Pkcs11ECCurve BrainpoolP512r1 => Get(Oids.Curves.BrainpoolP512r1);
        /// <summary>brainpoolP512t1.</summary>
        public static Pkcs11ECCurve BrainpoolP512t1 => Get(Oids.Curves.BrainpoolP512t1);

        /// <summary>SM2 (GB/T 32918), OID 1.2.156.10197.1.301.</summary>
        public static Pkcs11ECCurve Sm2 => Get(Oids.Curves.Sm2);

        // Every built-in curve, built once from Pkcs11CurveCatalog.Default so the names and field sizes
        // have one source. The properties read from here rather than being auto-properties: coverage
        // tools don't report an auto-property's compiler-generated getter or the static constructor its
        // initializer runs in, which left this whole class unmeasured.
        private static readonly FrozenDictionary<string, Pkcs11ECCurve> BuiltIn =
            Pkcs11CurveCatalog.Default.Curves.ToFrozenDictionary(c => c.Oid, FromInfo, StringComparer.Ordinal);

        private static Pkcs11ECCurve Get(string oid) => BuiltIn[oid];
    }
}
