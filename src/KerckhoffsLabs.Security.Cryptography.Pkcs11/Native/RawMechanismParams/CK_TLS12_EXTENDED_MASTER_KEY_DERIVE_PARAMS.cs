using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Parameters for CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE (PKCS#11 v3.2 / RFC 7627).
/// </summary>
[PlatformSpecificPack]
public struct CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS
{
    /// <summary>PRF mechanism (e.g. CKM_SHA256).</summary>
    public NativeCULong PrfHashMechanism;

    /// <summary>Pointer to the session-hash bytes.</summary>
    public IntPtr SessionHash;

    /// <summary>Length of session-hash in bytes.</summary>
    public NativeCULong SessionHashLen;

    /// <summary>Pointer to a CK_VERSION to be filled with the negotiated TLS version.</summary>
    public IntPtr Version;
}
