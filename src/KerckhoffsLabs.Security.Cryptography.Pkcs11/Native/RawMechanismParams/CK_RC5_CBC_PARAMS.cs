using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_RC5_CBC and CKM_RC5_CBC_PAD mechanisms
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_RC5_CBC_PARAMS
{
    /// <summary>
    /// Wordsize of RC5 cipher in bytes
    /// </summary>
    public NativeCULong Wordsize;

    /// <summary>
    /// Number of rounds of RC5 encipherment
    /// </summary>
    public NativeCULong Rounds;

    /// <summary>
    /// Pointer to initialization vector (IV) for CBC encryption
    /// </summary>
    public IntPtr Iv;

    /// <summary>
    /// Length of initialization vector (must be same as blocksize)
    /// </summary>
    public NativeCULong IvLen;
}