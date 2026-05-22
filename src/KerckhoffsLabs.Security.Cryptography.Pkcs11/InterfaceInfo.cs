namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A PKCS#11 v3.0 interface descriptor returned by <see cref="Pkcs11Library.GetInterfaces"/>.
/// Identifies an interface a module exposes — the standard <c>"PKCS 11"</c> interface or a
/// vendor-specific one — so callers can discover which interface tables a token offers.
/// </summary>
public sealed class InterfaceInfo
{
    /// <summary>The interface name (e.g. <c>"PKCS 11"</c>); empty when the module reports none.</summary>
    public string Name { get; }

    /// <summary>Raw interface flags (<c>CK_FLAGS</c>). Bit 0 is <c>CKF_INTERFACE_FORK_SAFE</c>.</summary>
    public ulong Flags { get; }

    /// <summary>True when the interface advertises <c>CKF_INTERFACE_FORK_SAFE</c> (flags bit 0).</summary>
    public bool IsForkSafe => (Flags & 0x00000001UL) != 0;

    internal InterfaceInfo(string name, ulong flags)
    {
        Name = name;
        Flags = flags;
    }
}
