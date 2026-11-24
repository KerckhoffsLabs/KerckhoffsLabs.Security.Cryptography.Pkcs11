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

    /// <summary>
    /// The version in the <c>CK_VERSION</c> header of the interface's function list: what tells a module's
    /// v2.40, v3.0 and v3.2 <c>"PKCS 11"</c> interfaces apart. <see langword="null"/> when the module hands back
    /// no function list.
    /// </summary>
    /// <remarks>
    /// Major and minor only, verbatim from the header, as <see cref="LibraryInfo.CryptokiVersion"/>: v3.2 is
    /// <c>(3, 2)</c> and v2.40 is <c>(2, 40)</c>. A vendor interface's table need not follow the standard layout
    /// past this header; its version is the vendor's.
    /// </remarks>
    public Version? Version { get; }

    internal InterfaceInfo(string name, ulong flags, Version? version = null)
    {
        Name = name;
        InterfaceFlags = new InterfaceFlags(flags);
        Version = version;
    }
}
