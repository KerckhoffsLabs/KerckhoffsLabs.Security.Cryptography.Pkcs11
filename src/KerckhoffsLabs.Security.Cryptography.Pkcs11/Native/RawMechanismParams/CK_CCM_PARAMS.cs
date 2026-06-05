using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_AES_CCM mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_CCM_PARAMS
{
    /// <summary>
    /// Length of the data
    /// </summary>
    public NativeCULong DataLen;

    /// <summary>
    /// Pointer to the nonce
    /// </summary>
    public IntPtr Nonce;

    /// <summary>
    /// Length of the nonce
    /// </summary>
    public NativeCULong NonceLen;

    /// <summary>
    /// Pointer to additional authentication data
    /// </summary>
    public IntPtr AAD;

    /// <summary>
    /// Length of additional authentication data
    /// </summary>
    public NativeCULong AADLen;

    /// <summary>
    /// Length of the MAC (output following cipher text) in bytes
    /// </summary>
    public NativeCULong MACLen;
}
