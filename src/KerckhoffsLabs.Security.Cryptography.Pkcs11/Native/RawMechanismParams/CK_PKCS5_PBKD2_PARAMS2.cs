using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Corrected structure that provides the parameters to the CKM_PKCS5_PBKD2 mechanism
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_PKCS5_PBKD2_PARAMS2
{
    /// <summary>
    /// Source of the salt value (CKZ)
    /// </summary>
    public NativeCULong SaltSource;

    /// <summary>
    /// Data used as the input for the salt source
    /// </summary>
    public IntPtr SaltSourceData;

    /// <summary>
    /// Length of the salt source input
    /// </summary>
    public NativeCULong SaltSourceDataLen;

    /// <summary>
    /// Number of iterations to perform when generating each block of random data
    /// </summary>
    public NativeCULong Iterations;

    /// <summary>
    /// Pseudo-random function to used to generate the key (CKP)
    /// </summary>
    public NativeCULong Prf;

    /// <summary>
    /// Data used as the input for PRF in addition to the salt value
    /// </summary>
    public IntPtr PrfData;

    /// <summary>
    /// Length of the input data for the PRF
    /// </summary>
    public NativeCULong PrfDataLen;

    /// <summary>
    /// Points to the password to be used in the PBE key generation
    /// </summary>
    public IntPtr Password;

    /// <summary>
    /// Length in bytes of the password information
    /// </summary>
    public NativeCULong PasswordLen;
}
