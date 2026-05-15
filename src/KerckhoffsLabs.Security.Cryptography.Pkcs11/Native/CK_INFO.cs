using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Provides general information about Cryptoki
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_INFO
{
    /// <summary>
    /// Cryptoki interface version number, for compatibility with future revisions of this interface.
    /// </summary>
    public CK_VERSION CryptokiVersion;

    /// <summary>
    /// ID of the Cryptoki library manufacturer. Must be padded with the blank character (‘ ‘). Should not be null-terminated.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] ManufacturerId;

    /// <summary>
    /// Bit flags reserved for future versions. Must be zero for this version
    /// </summary>
    public NativeCULong Flags;

    /// <summary>
    /// Character-string description of the library. Must be padded with the blank character (‘ ‘). Should not be null-terminated.
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] LibraryDescription;

    /// <summary>
    /// Cryptoki library version number
    /// </summary>
    public CK_VERSION LibraryVersion;
}