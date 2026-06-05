namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Profile identifier (PKCS#11 v3.0/v3.2 <c>CK_PROFILE_ID</c>). Used as the value of the
/// <see cref="CKA.CKA_PROFILE_ID"/> attribute on a profile object, naming a published profile a
/// token claims to implement. Distinct from the <see cref="CKP"/> enum (PBKDF2 pseudo-random
/// functions), which shares the <c>CKP_</c> prefix in the C headers but occupies a separate value
/// space.
/// </summary>
public enum CkpProfile : uint
{
    /// <summary>No profile / unset (<c>CKP_INVALID_ID</c>).</summary>
    CKP_INVALID_ID = 0x00000000,

    /// <summary>Baseline Provider: the minimal mandatory mechanism and function set.</summary>
    CKP_BASELINE_PROVIDER = 0x00000001,

    /// <summary>Extended Provider: Baseline plus the extended mechanism set.</summary>
    CKP_EXTENDED_PROVIDER = 0x00000002,

    /// <summary>Authentication Token: a token profile scoped to user-authentication use.</summary>
    CKP_AUTHENTICATION_TOKEN = 0x00000003,

    /// <summary>Public Certificates Token: a read-mostly store of public certificates.</summary>
    CKP_PUBLIC_CERTIFICATES_TOKEN = 0x00000004,

    /// <summary>Complete Provider: the full mechanism and function set.</summary>
    CKP_COMPLETE_PROVIDER = 0x00000005,

    /// <summary>HKDF/TLS Token: a profile for HKDF and TLS key-derivation use.</summary>
    CKP_HKDF_TLS_TOKEN = 0x00000006,
}
