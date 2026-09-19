namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// Salt source for HKDF-Extract (PKCS#11 v3.0 <c>CK_HKDF_PARAMS.saltType</c>).
/// </summary>
public enum HkdfSaltType : ulong
{
    /// <summary>No salt — HKDF uses a zero-filled salt the length of the PRF's output. Corresponds to <c>CKF_HKDF_SALT_NULL</c>.</summary>
    Null = 1,

    /// <summary>Salt supplied as raw bytes. Corresponds to <c>CKF_HKDF_SALT_DATA</c>.</summary>
    Data = 2,

    /// <summary>Salt supplied as a key handle. Corresponds to <c>CKF_HKDF_SALT_KEY</c>.</summary>
    Key = 4,
}
