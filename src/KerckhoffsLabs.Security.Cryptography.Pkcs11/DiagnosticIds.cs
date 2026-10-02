namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Diagnostic ids carried by the library's <see cref="ObsoleteAttribute"/>s, so a consumer with a
/// documented reason to use one legacy primitive can suppress exactly that one — instead of the
/// blanket <c>CS0618</c>, which would also hide every other obsoletion in their code — and by its
/// <see cref="System.Diagnostics.CodeAnalysis.ExperimentalAttribute"/>s (<c>KLPKCS115xx</c>), which
/// mark API shapes that may still change in a minor release.
/// </summary>
/// <remarks>
/// The ids are part of the public contract (a consumer's <c>#pragma warning disable</c> or
/// <c>NoWarn</c> references them by value) and are therefore stable: an id is never reused for a
/// different API, and an API never changes its id. An experimental id (<c>KLPKCS115xx</c>) names a feature
/// area rather than one member, so a project-wide suppression of it also covers members added to that area
/// later. Suppressing the compiler diagnostic does not
/// change the workspace's runtime crypto policy — the two are independent.
/// </remarks>
internal static class DiagnosticIds
{
    private const string DocsBase = "https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/";

    /// <summary>Format string resolving a diagnostic id to its documentation section.</summary>
    internal const string UrlFormat = DocsBase + "diagnostics.html#{0}";

    /// <summary>
    /// The page on enabling legacy algorithms for interop, which the obsoletion messages point to rather than
    /// carrying code; append a section anchor (<c>#des</c>, <c>#weak-curves</c>, …).
    /// </summary>
    internal const string LegacyAlgorithmsUrl = DocsBase + "legacy-algorithms.html";

    /// <summary>MD5 — broken hash function (practical collisions).</summary>
    internal const string Md5 = "KLPKCS11001";

    /// <summary>SHA-1 — broken hash function (SHAttered).</summary>
    internal const string Sha1 = "KLPKCS11002";

    /// <summary>Single DES — 56-bit key, exhaustively breakable.</summary>
    internal const string Des = "KLPKCS11003";

    /// <summary>Triple-DES — 64-bit block (Sweet32), NIST-deprecated.</summary>
    internal const string TripleDes = "KLPKCS11004";

    /// <summary>RC2 — weak legacy cipher with reduced effective key length.</summary>
    internal const string Rc2 = "KLPKCS11005";

    /// <summary>DSA — disallowed for signature generation by FIPS 186-5.</summary>
    internal const string Dsa = "KLPKCS11006";

    /// <summary>Named elliptic curves below the 128-bit security baseline.</summary>
    internal const string WeakEcCurve = "KLPKCS11007";

    /// <summary>
    /// <c>Rfc2898DeriveBytesPkcs11</c>'s instance constructors — not a security obsoletion (PBKDF2
    /// via the streaming <c>GetBytes</c> path is exactly as secure as the static one-shot path), but
    /// an API-shape one: mirrors the BCL's own <c>Rfc2898DeriveBytes</c>, whose eight constructors
    /// are all <c>[Obsolete]</c> in favor of its static <c>Pbkdf2</c> method.
    /// </summary>
    internal const string Rfc2898DeriveBytesPkcs11Constructors = "KLPKCS11011";

    /// <summary>
    /// The PKCS#11 v3.2 KEM surface whose shape may still change, because the v3.2 KEM functions are new and
    /// token support for them is still settling. It marks the KEM read-backs
    /// (<c>Pkcs11Key.EncapsulateAndExportSecret</c> / <c>DecapsulateAndExportSecret</c>), and any v3.2 KEM API
    /// added later.
    /// </summary>
    /// <remarks>
    /// The on-token <c>Pkcs11Key.EncapsulateKey</c> / <c>DecapsulateKey</c> are deliberately left unmarked: they
    /// were public before this id existed, so marking them would break existing callers' builds, and their shape
    /// (a template in, a sensitive key out) mirrors <c>Pkcs11Key.Derive</c> rather than the token-quirk-dependent
    /// read-back.
    /// </remarks>
    internal const string ExperimentalKem = "KLPKCS11501";
}
