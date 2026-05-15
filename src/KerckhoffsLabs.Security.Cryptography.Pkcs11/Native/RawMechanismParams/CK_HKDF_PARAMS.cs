using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_HKDF_DERIVE / CKM_HKDF_DATA / CKM_HKDF_KEY_GEN mechanisms (PKCS#11 v3.0).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_HKDF_PARAMS
{
    /// <summary>
    /// True to perform the HKDF-Extract step.
    /// </summary>
    [MarshalAs(UnmanagedType.U1)] public bool Extract;

    /// <summary>
    /// True to perform the HKDF-Expand step.
    /// </summary>
    [MarshalAs(UnmanagedType.U1)] public bool Expand;

    /// <summary>
    /// The PRF mechanism (typically a CKM_SHA*_HMAC variant).
    /// </summary>
    public NativeCULong PrfHashMechanism;

    /// <summary>
    /// Salt type: CKF_HKDF_SALT_NULL (1), CKF_HKDF_SALT_DATA (2), or CKF_HKDF_SALT_KEY (4).
    /// </summary>
    public NativeCULong SaltType;

    /// <summary>
    /// Pointer to salt data when SaltType = SALT_DATA.
    /// </summary>
    public IntPtr Salt;

    /// <summary>
    /// Length of the salt data in bytes.
    /// </summary>
    public NativeCULong SaltLen;

    /// <summary>
    /// Handle of the salt key when SaltType = SALT_KEY.
    /// </summary>
    public NativeCULong SaltKey;

    /// <summary>
    /// Pointer to the HKDF info (application-specific context bytes).
    /// </summary>
    public IntPtr Info;

    /// <summary>
    /// Length of the info in bytes.
    /// </summary>
    public NativeCULong InfoLen;
}
