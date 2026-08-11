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

    /// <summary>
    /// The version as a comparable <see cref="Version"/>, carrying the two fields verbatim. Ordering
    /// is preserved because both halves compare the raw <c>Minor</c> integer: a v3.01 module
    /// (<c>Minor = 1</c>) sorts below a v3.10 one (<c>Minor = 10</c>) either way. Build and revision
    /// are left unset — <c>CK_VERSION</c> has no such fields.
    /// </summary>
    public readonly Version ToVersion() => new(Major, Minor);

    // The spec-form rendering, for logs and the debugger only — it is deliberately not on the public
    // surface, because "3.02" versus "3.2" is exactly the ambiguity ToVersion exists to avoid.
    // Spec-wise the minor is the "hundredths" portion, so 1-99 are zero-padded (3.05) and 0 is a whole
    // version (3.0). D2 is a *minimum* width, so a module that exceeds 99 (e.g. NSS softoken's 3.125)
    // falls through the same format as a plain integer — a loadable module's version still parses.
    public override readonly string ToString()
        => Minor == 0
            ? string.Format("{0}.0", Major)
            : string.Format("{0}.{1:D2}", Major, Minor);
}
