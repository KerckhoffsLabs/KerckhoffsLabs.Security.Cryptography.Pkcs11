using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// PKCS#11 <c>CK_DATE</c>: a calendar date as fixed-width ASCII character fields
/// (<c>year</c> "1900"–"9999", <c>month</c> "01"–"12", <c>day</c> "01"–"31"). Blittable and
/// identical on every platform (all single-byte fields), so no Windows-packed sibling is needed.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct CK_DATE
{
    /// <summary>Year, four ASCII digits ("1900"–"9999").</summary>
    public Char4 Year;

    /// <summary>Month, two ASCII digits ("01"–"12").</summary>
    public Char2 Month;

    /// <summary>Day, two ASCII digits ("01"–"31").</summary>
    public Char2 Day;

    /// <summary>Fixed 4-byte inline buffer (replaces <c>fixed byte[4]</c> — no <c>unsafe</c>).</summary>
    [InlineArray(4)]
    internal struct Char4
    {
        private byte _element0;
    }

    /// <summary>Fixed 2-byte inline buffer (replaces <c>fixed byte[2]</c> — no <c>unsafe</c>).</summary>
    [InlineArray(2)]
    internal struct Char2
    {
        private byte _element0;
    }
}
