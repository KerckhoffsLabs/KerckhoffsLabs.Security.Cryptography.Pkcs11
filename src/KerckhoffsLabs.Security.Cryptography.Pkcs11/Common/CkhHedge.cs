namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Hedge-variant selector for ML-DSA / SLH-DSA signing (PKCS#11 v3.2). Carried as the
/// <c>hedgeVariant</c> field of <see cref="Native.RawMechanismParams.CK_SIGN_ADDITIONAL_CONTEXT"/>
/// and <see cref="Native.RawMechanismParams.CK_HASH_SIGN_ADDITIONAL_CONTEXT"/>.
/// </summary>
/// <remarks>
/// Spec-side this enum's identifiers are CKH_* (CKH_HEDGE_PREFERRED, CKH_HEDGE_REQUIRED,
/// CKH_DETERMINISTIC_REQUIRED), reusing the historical CKH_* prefix for a different
/// attribute context. The C# enum is renamed <see cref="CkhHedge"/> to avoid colliding
/// with the existing hardware-feature <see cref="CKH"/> enum.
/// </remarks>
public enum CkhHedge : uint
{
    /// <summary>Token chooses hedged (randomized) signing when possible; falls back to deterministic if no RNG seed is available. Default per FIPS 204 §3.6.</summary>
    CKH_HEDGE_PREFERRED = 0x00000000,

    /// <summary>Hedged signing is mandatory; <see cref="CKR.CKR_SEED_RANDOM_REQUIRED"/> is returned if no RNG seed is available.</summary>
    CKH_HEDGE_REQUIRED = 0x00000001,

    /// <summary>Deterministic signing is mandatory (no randomness used).</summary>
    CKH_DETERMINISTIC_REQUIRED = 0x00000002,
}
