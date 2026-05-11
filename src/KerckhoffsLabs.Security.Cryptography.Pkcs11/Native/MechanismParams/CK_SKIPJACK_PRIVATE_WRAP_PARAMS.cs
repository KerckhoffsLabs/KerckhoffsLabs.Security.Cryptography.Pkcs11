using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

/// <summary>
/// Structure that provides the parameters to the CKM_SKIPJACK_PRIVATE_WRAP mechanism
/// </summary>
[PlatformSpecificPack]
public struct CK_SKIPJACK_PRIVATE_WRAP_PARAMS
{
    /// <summary>
    /// Length of the password
    /// </summary>
    public NativeCULong PasswordLen;
    
    /// <summary>
    /// Pointer to the buffer which contains the user-supplied password
    /// </summary>
    public IntPtr Password;

    /// <summary>
    /// Other party's key exchange public key size
    /// </summary>
    public NativeCULong PublicDataLen;

    /// <summary>
    /// Pointer to other party's key exchange public key value
    /// </summary>
    public IntPtr PublicData;
    
    /// <summary>
    /// Length of prime and base values
    /// </summary>
    public NativeCULong PAndGLen;

    /// <summary>
    /// Length of subprime value
    /// </summary>
    public NativeCULong QLen;

    /// <summary>
    /// Size of random Ra, in bytes
    /// </summary>
    public NativeCULong RandomLen;

    /// <summary>
    /// Pointer to Ra data
    /// </summary>
    public IntPtr RandomA;

    /// <summary>
    /// Pointer to Prime, p, value
    /// </summary>
    public IntPtr PrimeP;

    /// <summary>
    /// Pointer to Base, g, value
    /// </summary>
    public IntPtr BaseG;

    /// <summary>
    /// Pointer to Subprime, q, value
    /// </summary>
    public IntPtr SubprimeQ;
}