using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_KEA_DERIVE mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_KEA_DERIVE_PARAMS
{
    /// <summary>
    /// Option for generating the key (called a TEK). True if the sender (originator) generates the TEK, false if the recipient is regenerating the TEK.
    /// </summary>
    [MarshalAs(UnmanagedType.U1)]
    public bool IsSender;

    /// <summary>
    /// Size of random Ra and Rb, in bytes
    /// </summary>
    public NativeCULong RandomLen;

    /// <summary>
    /// Pointer to Ra data
    /// </summary>
    public IntPtr RandomA;

    /// <summary>
    /// Pointer to Rb data
    /// </summary>
    public IntPtr RandomB;

    /// <summary>
    /// Other party's KEA public key size
    /// </summary>
    public NativeCULong PublicDataLen;

    /// <summary>
    /// Pointer to other party's KEA public key value
    /// </summary>
    public IntPtr PublicData;
}