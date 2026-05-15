using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Describes the version
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
public partial struct CK_VERSION
{
    /// <summary>
    /// Major version number (the integer portion of the version)
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
    public byte[] Major;

    /// <summary>
    /// Minor version number (the hundredths portion of the version)
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
    public byte[] Minor;

    /// <summary>
    /// Returns a string that represents the current CK_VERSION structure.
    /// </summary>
    /// <returns>String that represents the current CK_VERSION structure.</returns>
    public override string ToString()
    {
        if (Minor[0] == 0x00)
        {
            return string.Format("{0}.{1}", Major[0], Minor[0]);
        }
        else if (Minor[0] <= 0x63)
        {
            return string.Format("{0}.{1:D2}", Major[0], Minor[0]);
        }
        else
        {
            return "Invalid version";
        }
    }
}