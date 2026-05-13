using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Sub-struct describing the counter encoding for SP800-108 KDFs (PKCS#11 v3.0).
/// </summary>
[PlatformSpecificPack]
public struct CK_SP800_108_COUNTER_FORMAT
{
    /// <summary>
    /// True for little-endian byte order; false for big-endian.
    /// </summary>
    [MarshalAs(UnmanagedType.U1)] public bool LittleEndian;

    /// <summary>
    /// Counter width in bits (e.g. 32).
    /// </summary>
    public NativeCULong WidthInBits;
}
