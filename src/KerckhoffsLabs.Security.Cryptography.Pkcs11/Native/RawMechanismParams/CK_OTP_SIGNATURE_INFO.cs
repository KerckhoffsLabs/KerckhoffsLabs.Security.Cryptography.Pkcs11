using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that is returned by all OTP mechanisms in successful calls to C_Sign (C_SignFinal)
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_OTP_SIGNATURE_INFO
{
    /// <summary>
    /// Pointer to an array of OTP parameter values (CK_OTP_PARAM structures)
    /// </summary>
    public IntPtr Params;

    /// <summary>
    /// The number of parameters in the array
    /// </summary>
    public NativeCULong Count;
}