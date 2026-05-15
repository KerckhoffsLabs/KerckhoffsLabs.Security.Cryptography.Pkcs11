using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_KEY_WRAP_SET_OAEP mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_KEY_WRAP_SET_OAEP_PARAMS
{
    /// <summary>
    /// Block contents byte
    /// </summary>
    public byte BC;

    /// <summary>
    /// Concatenation of hash of plaintext data (if present) and extra data (if present)
    /// </summary>
    public IntPtr X;

    /// <summary>
    /// Length in bytes of concatenation of hash of plaintext data (if present) and extra data (if present) or 0 if neither is present
    /// </summary>
    public NativeCULong XLen;
}