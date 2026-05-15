using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Optional arguments for the C_Initialize function. Declared as a value-type struct
/// so the runtime gives it a sequential layout (matches the pattern used by every
/// other CK_* native struct in this codebase). The previous class declaration carried
/// only the [PlatformSpecificPack] marker, which is decorative — classes need an
/// explicit [StructLayout] to be marshalable, and without one Marshal.SizeOf failed
/// the moment the struct was actually passed to C_Initialize.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_C_INITIALIZE_ARGS
{
    /// <summary>Pointer to a function to use for creating mutex objects (not supported).</summary>
    public IntPtr CreateMutex;

    /// <summary>Pointer to a function to use for destroying mutex objects (not supported).</summary>
    public IntPtr DestroyMutex;

    /// <summary>Pointer to a function to use for locking mutex objects (not supported).</summary>
    public IntPtr LockMutex;

    /// <summary>Pointer to a function to use for unlocking mutex objects (not supported).</summary>
    public IntPtr UnlockMutex;

    /// <summary>Bit flags specifying options (e.g. <c>CKF_OS_LOCKING_OK</c>).</summary>
    public NativeCULong Flags;

    /// <summary>Reserved for future use.</summary>
    public IntPtr Reserved;
}
