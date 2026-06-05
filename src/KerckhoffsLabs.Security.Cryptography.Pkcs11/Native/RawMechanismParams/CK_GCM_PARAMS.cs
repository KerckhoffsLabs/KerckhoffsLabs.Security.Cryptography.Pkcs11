using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_AES_GCM mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_GCM_PARAMS
{
    /// <summary>
    /// Pointer to initialization vector
    /// </summary>
    public IntPtr Iv;

    /// <summary>
    /// Length of initialization vector in bytes
    /// </summary>
    public NativeCULong IvLen;

    /// <summary>
    /// Length of initialization vector in bits. PKCS#11 v3.2 (§2.5.13, CK_GCM_PARAMS) retains this
    /// as a legacy field whose value "may be 0"; the IV length is taken from <see cref="IvLen"/>.
    /// Many tokens ignore it and some reject a non-zero value, so it should be left 0.
    /// </summary>
    public NativeCULong IvBits;

    /// <summary>
    /// Pointer to additional authentication data
    /// </summary>
    public IntPtr AAD;

    /// <summary>
    /// Length of additional authentication data in bytes
    /// </summary>
    public NativeCULong AADLen;

    /// <summary>
    /// Length of authentication tag (output following cipher text) in bits
    /// </summary>
    public NativeCULong TagBits;
}
