using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure which provides all of the necessary information required by the CKM_PBE mechanisms and the CKM_PBA_SHA1_WITH_SHA1_HMAC mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_PBE_PARAMS
{
    /// <summary>
    /// Pointer to the location that receives the 8-byte initialization vector (IV), if an IV is required
    /// </summary>
    public IntPtr InitVector;

    /// <summary>
    /// Points to the password to be used in the PBE key generation
    /// </summary>
    public IntPtr Password;

    /// <summary>
    /// Length in bytes of the password information
    /// </summary>
    public NativeCULong PasswordLen;

    /// <summary>
    /// Points to the salt to be used in the PBE key generation
    /// </summary>
    public IntPtr Salt;

    /// <summary>
    /// Length in bytes of the salt information
    /// </summary>
    public NativeCULong SaltLen;

    /// <summary>
    /// Number of iterations required for the generation
    /// </summary>
    public NativeCULong Iteration;
}