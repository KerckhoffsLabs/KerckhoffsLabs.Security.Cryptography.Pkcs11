using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// One data parameter for an SP800-108 KDF data sequence (PKCS#11 v3.0).
/// </summary>
[PlatformSpecificPack]
public struct CK_PRF_DATA_PARAM
{
    /// <summary>
    /// Data-type tag: CK_SP800_108_BYTE_ARRAY (1), CK_SP800_108_COUNTER (2), CK_SP800_108_DKM_LENGTH (4), CK_SP800_108_BYTE_ARRAY (8), or CK_SP800_108_COUNTER_FORMAT/DKM_LENGTH_FORMAT pointer types.
    /// </summary>
    public NativeCULong Type;

    /// <summary>
    /// Pointer to the data (byte array or a format struct, depending on Type).
    /// </summary>
    public IntPtr Value;

    /// <summary>
    /// Length of the data in bytes.
    /// </summary>
    public NativeCULong ValueLen;
}
