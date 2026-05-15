using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that includes the type, value and length of an OTP parameter
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_OTP_PARAM
{
    /// <summary>
    /// Parameter type
    /// </summary>
    public NativeCULong Type;

    /// <summary>
    /// Pointer to the value of the parameter
    /// </summary>
    public IntPtr Value;

    /// <summary>
    /// Length in bytes of the value
    /// </summary>
    public NativeCULong ValueLen;
}