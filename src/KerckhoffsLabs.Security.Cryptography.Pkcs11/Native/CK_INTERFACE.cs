using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Versioned interface descriptor returned by C_GetInterface (PKCS#11 v3.0 §5.4.5).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_INTERFACE
{
    /// <summary>Pointer to a null-terminated UTF-8 interface name (typically "PKCS 11").</summary>
    public IntPtr InterfaceName;

    /// <summary>Pointer to the function-list struct (CK_FUNCTION_LIST or CK_FUNCTION_LIST_3_0).</summary>
    public IntPtr FunctionList;

    /// <summary>Interface flags (bit 0 = CKF_INTERFACE_FORK_SAFE).</summary>
    public NativeCULong Flags;
}
