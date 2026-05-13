using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_IKE1_EXTENDED_DERIVE mechanism — IKEv1 extended derivation (PKCS#11 v3.0).
/// </summary>
[PlatformSpecificPack]
public struct CK_IKE1_EXTENDED_DERIVE_PARAMS
{
    /// <summary>
    /// PRF mechanism.
    /// </summary>
    public NativeCULong PrfMechanism;

    /// <summary>
    /// True if Keygxy is valid.
    /// </summary>
    [MarshalAs(UnmanagedType.U1)] public bool HasKeygxy;

    /// <summary>
    /// Handle of the shared-secret key g^xy.
    /// </summary>
    public NativeCULong Keygxy;

    /// <summary>
    /// Pointer to additional input data.
    /// </summary>
    public IntPtr ExtraData;

    /// <summary>
    /// Length of ExtraData in bytes.
    /// </summary>
    public NativeCULong ExtraDataLen;
}
