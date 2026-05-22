using System.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>
/// Helpers for building the fixed-width native PKCS#11 structs that the decode tests assert against.
/// Ambient (assembly-root namespace) so any test can use it without an extra <c>using</c>.
/// </summary>
internal static class NativeTestStructs
{
    /// <summary>
    /// Writes <paramref name="value"/> as UTF-8 into <paramref name="dest"/>, space-padding the
    /// remainder — the PKCS#11 convention for fixed-width string fields (label, manufacturer, …).
    /// </summary>
    public static void FillPadded(Span<byte> dest, string value)
    {
        dest.Fill((byte)' ');
        Encoding.UTF8.GetBytes(value, dest);
    }
}
