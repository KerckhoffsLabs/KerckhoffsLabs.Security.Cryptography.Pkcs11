using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Flags describing a PKCS#11 interface (the <c>CK_INTERFACE</c> flags from <c>C_GetInterfaceList</c>).
/// </summary>
public sealed record InterfaceFlags
{
    /// <summary>Raw interface flags (<c>CK_FLAGS</c>).</summary>
    public ulong Flags { get; }

    /// <summary>True if the interface's functions are safe to call from a child process after <c>fork()</c>.</summary>
    public bool ForkSafe
        => (Flags & CKF.CKF_INTERFACE_FORK_SAFE.Value) == CKF.CKF_INTERFACE_FORK_SAFE.Value;

    internal InterfaceFlags(NativeCULong flags) => Flags = (ulong)flags;
}
