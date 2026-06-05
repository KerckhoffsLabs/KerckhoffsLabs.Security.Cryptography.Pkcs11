using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_SKIPJACK_RELAYX mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_SKIPJACK_RELAYX_PARAMS
{
    /// <summary>
    /// Length of old wrapped key in bytes
    /// </summary>
    public NativeCULong OldWrappedXLen;

    /// <summary>
    /// Pointer to old wrapper key
    /// </summary>
    public IntPtr OldWrappedX;

    /// <summary>
    /// Length of the old password
    /// </summary>
    public NativeCULong OldPasswordLen;

    /// <summary>
    /// Pointer to the buffer which contains the old user-supplied password
    /// </summary>
    public IntPtr OldPassword;

    /// <summary>
    /// Old key exchange public key size
    /// </summary>
    public NativeCULong OldPublicDataLen;

    /// <summary>
    /// Pointer to old key exchange public key value
    /// </summary>
    public IntPtr OldPublicData;

    /// <summary>
    /// Size of old random Ra in bytes
    /// </summary>
    public NativeCULong OldRandomLen;

    /// <summary>
    /// Pointer to old Ra data
    /// </summary>
    public IntPtr OldRandomA;

    /// <summary>
    /// Length of the new password
    /// </summary>
    public NativeCULong NewPasswordLen;

    /// <summary>
    /// Pointer to the buffer which contains the new usersupplied password
    /// </summary>
    public IntPtr NewPassword;

    /// <summary>
    /// New key exchange public key size
    /// </summary>
    public NativeCULong NewPublicDataLen;

    /// <summary>
    /// Pointer to new key exchange public key value
    /// </summary>
    public IntPtr NewPublicData;

    /// <summary>
    /// Size of new random Ra in bytes
    /// </summary>
    public NativeCULong NewRandomLen;

    /// <summary>
    /// Pointer to new Ra data
    /// </summary>
    public IntPtr NewRandomA;
}
