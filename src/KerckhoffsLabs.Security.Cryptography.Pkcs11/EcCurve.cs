namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Named elliptic curves. Each value maps to the standard <c>CKA_EC_PARAMS</c> OID
/// encoding used when generating an EC key pair. Vendor-specific or less common curves
/// can still be selected by supplying an explicit <c>CKA_EC_PARAMS</c> attribute in the
/// key-generation template instead.
/// </summary>
public enum EcCurve
{
    /// <summary>secp256r1 / prime256v1 / P-256 (FIPS 186-4). Recommended for most use cases.</summary>
    P256,
    /// <summary>secp384r1 / P-384 (FIPS 186-4).</summary>
    P384,
    /// <summary>secp521r1 / P-521 (FIPS 186-4).</summary>
    P521,
}
