using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_SP800_108_FEEDBACK_KDF mechanism (PKCS#11 v3.0). Identical to CK_SP800_108_KDF_PARAMS plus an IV.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_SP800_108_FEEDBACK_KDF_PARAMS
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
    /// Length of the IV in bytes.
    /// </summary>
    public NativeCULong IVLen;

    /// <summary>
    /// Pointer to the IV used to seed the feedback chain.
    /// </summary>
    public IntPtr IV;

    /// <summary>
    /// Number of entries in AdditionalDerivedKeys array.
    /// </summary>
    public NativeCULong AdditionalDerivedKeys;

    /// <summary>
    /// Pointer to an array of CK_DERIVED_KEY for sibling keys derived in the same call.
    /// </summary>
    public IntPtr AdditionalDerivedKeysPtr;
}
