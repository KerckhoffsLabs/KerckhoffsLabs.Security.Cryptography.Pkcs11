using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Provides information about a particular mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_MECHANISM_INFO
{
    /// <summary>
    /// The minimum size of the key for the mechanism (whether this is measured in bits or in bytes is mechanism-dependent)
    /// </summary>
    public NativeCULong MinKeySize;

    /// <summary>
    /// The maximum size of the key for the mechanism (whether this is measured in bits or in bytes is mechanism-dependent)
    /// </summary>
    public NativeCULong MaxKeySize;

    /// <summary>
    /// Bit flags specifying mechanism capabilities
    /// </summary>
    public NativeCULong Flags;
}