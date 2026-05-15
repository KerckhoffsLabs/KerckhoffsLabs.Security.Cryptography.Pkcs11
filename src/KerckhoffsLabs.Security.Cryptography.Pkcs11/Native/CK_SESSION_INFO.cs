using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Information about a session
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_SESSION_INFO
{
    /// <summary>
    /// ID of the slot that interfaces with the token
    /// </summary>
    public NativeCULong SlotId;

    /// <summary>
    /// The state of the session
    /// </summary>
    public NativeCULong State;

    /// <summary>
    /// Bit flags that define the type of session
    /// </summary>
    public NativeCULong Flags;

    /// <summary>
    /// An error code defined by the cryptographic device. Used for errors not covered by Cryptoki.
    /// </summary>
    public NativeCULong DeviceError;
}