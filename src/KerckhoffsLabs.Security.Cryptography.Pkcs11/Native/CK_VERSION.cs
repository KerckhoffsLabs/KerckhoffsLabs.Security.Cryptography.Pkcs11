using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Describes the version. Blittable: two single-byte fields with identical layout on every
/// platform (byte alignment), so it needs no <c>[PackedForPkcs11]</c> sibling.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct CK_VERSION
{
    /// <summary>Major version number (integer portion).</summary>
    public byte Major;
    /// <summary>Minor version number (hundredths portion).</summary>
    public byte Minor;

    public override readonly string ToString()
    {
        if (Minor == 0x00) return string.Format("{0}.{1}", Major, Minor);
        if (Minor <= 0x63) return string.Format("{0}.{1:D2}", Major, Minor);
        return "Invalid version";
    }
}
