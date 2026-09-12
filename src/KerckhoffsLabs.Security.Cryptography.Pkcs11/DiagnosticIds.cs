namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Diagnostic ids carried by the library's <see cref="ObsoleteAttribute"/>s, so a consumer with a
/// documented reason to use one legacy primitive can suppress exactly that one — instead of the
/// blanket <c>CS0618</c>, which would also hide every other obsoletion in their code.
/// </summary>
/// <remarks>
/// The ids are part of the public contract (a consumer's <c>#pragma warning disable</c> or
/// <c>NoWarn</c> references them by value) and are therefore stable: an id is never reused for a
/// different API, and an API never changes its id. Suppressing the compiler diagnostic does not
/// disable the runtime <c>AllowInsecure</c> gate — the two are independent.
/// </remarks>
internal static class DiagnosticIds
{
    /// <summary>Format string resolving a diagnostic id to its documentation section.</summary>
    internal const string UrlFormat =
        "https://kerckhoffslabs.github.io/KerckhoffsLabs.Security.Cryptography.Pkcs11/diagnostics.html#{0}";

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
}
