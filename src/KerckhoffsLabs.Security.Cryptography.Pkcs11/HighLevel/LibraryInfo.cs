using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// General information about PKCS#11 library (CK_INFO)
/// </summary>
public class LibraryInfo
{
    /// <summary>
    /// Cryptoki interface version number
    /// </summary>
    protected string? _cryptokiVersion = null;

    /// <summary>
    /// Cryptoki interface version number
    /// </summary>
    public string? CryptokiVersion
    {
        get
        {
            return _cryptokiVersion;
        }
    }

    /// <summary>
    /// ID of the Cryptoki library manufacturer
    /// </summary>
    protected string? _manufacturerId = null;

    /// <summary>
    /// ID of the Cryptoki library manufacturer
    /// </summary>
    public string? ManufacturerId
    {
        get
        {
            return _manufacturerId;
        }
    }

    /// <summary>
    /// Bit flags reserved for future versions
    /// </summary>
    protected NativeCULong _flags = new(0);

    /// <summary>
    /// Bit flags reserved for future versions
    /// </summary>
    public ulong Flags
    {
        get
        {
            return Convert.ToUInt64(_flags);
        }
    }

    /// <summary>
    /// Description of the library
    /// </summary>
    protected string? _libraryDescription = null;

    /// <summary>
    /// Description of the library
    /// </summary>
    public string? LibraryDescription
    {
        get
        {
            return _libraryDescription;
        }
    }

    /// <summary>
    /// Cryptoki library version number
    /// </summary>
    protected string? _libraryVersion = null;
    
    /// <summary>
    /// Cryptoki library version number
    /// </summary>
    public string? LibraryVersion
    {
        get
        {
            return _libraryVersion;
        }
    }

    /// <summary>
    /// Converts low level CK_INFO structure to high level LibraryInfo class
    /// </summary>
    /// <param name="ck_info">Low level CK_INFO structure</param>
    protected internal LibraryInfo(CK_INFO ck_info)
    {
        _cryptokiVersion = ck_info.CryptokiVersion.ToString();
        _manufacturerId = ConvertUtils.BytesToUtf8String(ck_info.ManufacturerId, true);
        _flags = ck_info.Flags;
        _libraryDescription = ConvertUtils.BytesToUtf8String(ck_info.LibraryDescription, true);
        _libraryVersion = ck_info.LibraryVersion.ToString();
    }
}