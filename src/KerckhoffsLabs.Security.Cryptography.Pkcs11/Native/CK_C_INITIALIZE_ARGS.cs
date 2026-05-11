using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Optional arguments for the C_Initialize function
/// </summary>
[PlatformSpecificPack]
public class CK_C_INITIALIZE_ARGS
{
    /// <summary>
    /// Pointer to a function to use for creating mutex objects (not supported by Pkcs11Interop)
    /// </summary>
    public IntPtr CreateMutex = IntPtr.Zero;

    /// <summary>
    /// Pointer to a function to use for destroying mutex objects (not supported by Pkcs11Interop)
    /// </summary>
    public IntPtr DestroyMutex = IntPtr.Zero;

    /// <summary>
    /// Pointer to a function to use for locking mutex objects (not supported by Pkcs11Interop)
    /// </summary>
    public IntPtr LockMutex = IntPtr.Zero;

    /// <summary>
    /// Pointer to a function to use for unlocking mutex objects (not supported by Pkcs11Interop)
    /// </summary>
    public IntPtr UnlockMutex = IntPtr.Zero;

    /// <summary>
    /// Bit flags specifying options
    /// </summary>
    public NativeCULong Flags = new(0);

    /// <summary>
    /// Reserved for future use
    /// </summary>
    public IntPtr Reserved = IntPtr.Zero;
}