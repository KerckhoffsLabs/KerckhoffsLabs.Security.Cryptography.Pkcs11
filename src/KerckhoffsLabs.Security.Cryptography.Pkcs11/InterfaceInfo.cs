namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A PKCS#11 v3.0 interface descriptor returned by <see cref="Pkcs11Library.GetInterfaces"/>.
/// Identifies an interface a module exposes — the standard <c>"PKCS 11"</c> interface or a
/// vendor-specific one — so callers can discover which interface tables a token offers.
/// </summary>
public sealed record InterfaceInfo
{
    /// <summary>The interface name (e.g. <c>"PKCS 11"</c>); empty when the module reports none.</summary>
    public string Name { get; }

    /// <summary>Flags describing the interface.</summary>
    public InterfaceFlags InterfaceFlags { get; }

    internal InterfaceInfo(string name, NativeCULong flags)
    {
        Name = name;
        InterfaceFlags = new InterfaceFlags(flags);
    }
}
