using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// General information about the loaded PKCS#11 library (CK_INFO).
/// </summary>
public sealed record LibraryInfo
{
    /// <summary>Cryptoki interface version number.</summary>
    public string CryptokiVersion { get; }

    /// <summary>ID of the Cryptoki library manufacturer.</summary>
    public string ManufacturerId { get; }

    /// <summary>Bit flags reserved for future versions.</summary>
    public ulong Flags { get; }

    /// <summary>Description of the library.</summary>
    public string LibraryDescription { get; }

    /// <summary>Cryptoki library version number.</summary>
    public string LibraryVersion { get; }

    internal LibraryInfo(CK_INFO ck_info)
    {
        CryptokiVersion = ck_info.CryptokiVersion.ToString();
        ManufacturerId = System.Text.Encoding.UTF8.GetString(ck_info.ManufacturerId).TrimEnd();
        Flags = (ulong)ck_info.Flags;
        LibraryDescription = System.Text.Encoding.UTF8.GetString(ck_info.LibraryDescription).TrimEnd();
        LibraryVersion = ck_info.LibraryVersion.ToString();
    }
}
