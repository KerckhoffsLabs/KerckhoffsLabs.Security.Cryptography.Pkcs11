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

    // Spec-wise the minor is the "hundredths" portion, so 1-99 are zero-padded (3.05) and 0 is a whole
    // version (3.0). D2 is a *minimum* width, so a module that exceeds 99 (e.g. NSS softoken's 3.125)
    // falls through the same format as a plain integer — a loadable module's version still parses.
    public override readonly string ToString()
        => Minor == 0
            ? string.Format("{0}.0", Major)
            : string.Format("{0}.{1:D2}", Major, Minor);
}
