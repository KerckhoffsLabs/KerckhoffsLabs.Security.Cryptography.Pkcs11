using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Defines the type, value, and length of an attribute
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_ATTRIBUTE
{
    /// <summary>
    /// The attribute type
    /// </summary>
    public NativeCULong type;

    /// <summary>
    /// Pointer to the value of the attribute
    /// </summary>
    public IntPtr value;

    /// <summary>
    /// Length in bytes of the value
    /// </summary>
    public NativeCULong valueLen;
}