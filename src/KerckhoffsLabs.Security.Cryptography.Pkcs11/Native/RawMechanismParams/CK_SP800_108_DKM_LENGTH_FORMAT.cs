using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Sub-struct describing the DKM-length encoding for SP800-108 KDFs (PKCS#11 v3.0).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_SP800_108_DKM_LENGTH_FORMAT
{
    /// <summary>
    /// Method for encoding DKM length: CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS (1) or CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS (2).
    /// </summary>
    public NativeCULong DkmLengthMethod;

    /// <summary>
    /// True for little-endian byte order; false for big-endian.
    /// </summary>
    [MarshalAs(UnmanagedType.U1)] public bool LittleEndian;

    /// <summary>
    /// Encoded-length width in bits.
    /// </summary>
    public NativeCULong WidthInBits;
}
