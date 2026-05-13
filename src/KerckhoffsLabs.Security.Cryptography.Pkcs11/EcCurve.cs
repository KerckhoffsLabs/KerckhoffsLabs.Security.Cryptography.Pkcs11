namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Named curves supported by the <see cref="Session.GenerateEcKeyPair"/> secure helper.
/// Vendor-specific or less common curves can still be generated via <see cref="Session.GenerateKeyPair"/>
/// with an explicit <c>CKA_EC_PARAMS</c> attribute.
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
