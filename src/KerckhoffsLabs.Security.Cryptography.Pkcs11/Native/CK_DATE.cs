using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// PKCS#11 <c>CK_DATE</c>: a calendar date as fixed-width ASCII character fields
/// (<c>year</c> "1900"–"9999", <c>month</c> "01"–"12", <c>day</c> "01"–"31"). Blittable and
/// identical on every platform (all single-byte fields), so no Windows-packed sibling is needed.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct CK_DATE
{
    /// <summary>Year, four ASCII digits ("1900"–"9999").</summary>
    public fixed byte Year[4];

    /// <summary>Month, two ASCII digits ("01"–"12").</summary>
    public fixed byte Month[2];

    /// <summary>Day, two ASCII digits ("01"–"31").</summary>
    public fixed byte Day[2];
}
