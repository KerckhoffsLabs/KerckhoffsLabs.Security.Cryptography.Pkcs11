using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

/// <summary>
/// Structure which provides information about the random data of a client and a server in an SSL context
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_SSL3_RANDOM_DATA
{
    /// <summary>
    /// Pointer to the client's random data
    /// </summary>
    public IntPtr ClientRandom;

    /// <summary>
    /// Length in bytes of the client's random data
    /// </summary>
    public NativeCULong ClientRandomLen;

    /// <summary>
    /// Pointer to the server's random data
    /// </summary>
    public IntPtr ServerRandom;

    /// <summary>
    /// Length in bytes of the server's random data
    /// </summary>
    public NativeCULong ServerRandomLen;
}