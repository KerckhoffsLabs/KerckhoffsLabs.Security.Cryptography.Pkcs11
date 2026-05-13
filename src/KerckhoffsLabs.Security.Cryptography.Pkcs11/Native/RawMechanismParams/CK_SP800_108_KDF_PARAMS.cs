using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_SP800_108_COUNTER_KDF and CKM_SP800_108_DOUBLE_PIPELINE_KDF mechanisms (PKCS#11 v3.0).
/// </summary>
[PlatformSpecificPack]
public struct CK_SP800_108_KDF_PARAMS
{
    /// <summary>
    /// The PRF mechanism (a CKM_*_HMAC variant or CKM_AES_CMAC).
    /// </summary>
    public NativeCULong PrfType;

    /// <summary>
    /// Number of entries in DataParams.
    /// </summary>
    public NativeCULong NumberOfDataParams;

    /// <summary>
    /// Pointer to an array of CK_PRF_DATA_PARAM describing the PRF input sequence.
    /// </summary>
    public IntPtr DataParams;

    /// <summary>
    /// Number of entries in AdditionalDerivedKeys array.
    /// </summary>
    public NativeCULong AdditionalDerivedKeys;

    /// <summary>
    /// Pointer to an array of CK_DERIVED_KEY for sibling keys derived in the same call.
    /// </summary>
    public IntPtr AdditionalDerivedKeysPtr;
}
