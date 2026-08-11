using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// General information about the loaded PKCS#11 library (CK_INFO).
/// </summary>
public sealed record LibraryInfo
{
    /// <summary>
    /// Version of the Cryptoki interface this library is compatible with — the datum that decides
    /// which of v2.40 / v3.0 / v3.1 / v3.2 you are talking to. <c>CK_VERSION</c>'s minor field is the
    /// hundredths portion, so a module the vendor documents as "3.01" reports
    /// <see cref="Version.Minor"/> <c>1</c> and one documented as "3.10" reports <c>10</c>; comparing
    /// <see cref="Version"/> values orders them correctly either way.
    /// </summary>
    public Version CryptokiVersion { get; }

    /// <summary>ID of the Cryptoki library manufacturer.</summary>
    public string ManufacturerId { get; }

    /// <summary>Bit flags reserved for future versions.</summary>
    public LibraryFlags LibraryFlags { get; }

    /// <summary>Description of the library.</summary>
    public string LibraryDescription { get; }

    /// <summary>Version number of the library itself, as reported by its vendor. See
    /// <see cref="CryptokiVersion"/> for how <c>CK_VERSION</c> encodes the minor field.</summary>
    public Version LibraryVersion { get; }

    internal LibraryInfo(CK_INFO ck_info)
    {
        CryptokiVersion = ck_info.CryptokiVersion.ToVersion();
        ManufacturerId = Encoding.UTF8.GetString(ck_info.ManufacturerId).TrimEnd();
        LibraryFlags = new LibraryFlags((ulong)ck_info.Flags);
        LibraryDescription = Encoding.UTF8.GetString(ck_info.LibraryDescription).TrimEnd();
        LibraryVersion = ck_info.LibraryVersion.ToVersion();
    }
}
