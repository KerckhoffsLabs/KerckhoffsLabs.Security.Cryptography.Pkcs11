using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that is used to provide parameters for OTP mechanisms in a generic fashion
/// </summary>
[PlatformSpecificPack]
public struct CK_OTP_PARAMS
{
    /// <summary>
    /// Pointer to an array of OTP parameters (CK_OTP_PARAM structures)
    /// </summary>
    public IntPtr Params;

    /// <summary>
    /// The number of parameters in the array
    /// </summary>
    public NativeCULong Count;
}