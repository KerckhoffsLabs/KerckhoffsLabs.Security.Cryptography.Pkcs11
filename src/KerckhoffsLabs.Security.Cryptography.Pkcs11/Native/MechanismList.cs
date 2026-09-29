using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Converts the native <c>CK_MECHANISM_TYPE</c> list <c>C_GetMechanismList</c> fills into the
/// <see cref="CKM"/>-typed list the managed API returns.
/// </summary>
internal static class MechanismList
{
    /// <summary>
    /// Copies the entries the module returned into <paramref name="destination"/>, compacted, and returns
    /// how many were kept.
    /// </summary>
    /// <remarks>
    /// Values are cast without validation, so vendor-defined mechanisms and standard ones newer than the
    /// enum survive as unnamed <see cref="CKM"/> values. The one exception is a value wider than 32 bits,
    /// legal where <c>CK_ULONG</c> is 64 bits: <see cref="CKM"/> cannot hold it, so it is left out rather
    /// than truncated into a different mechanism or overflowing mid-enumeration.
    /// </remarks>
    /// <param name="native">The buffer the module filled.</param>
    /// <param name="returned">The count the module reported; entries past it (or past either buffer) are ignored.</param>
    /// <param name="destination">Receives the kept values, from index 0.</param>
    /// <returns>The number of values written to <paramref name="destination"/>.</returns>
    public static int CopyRepresentable(ReadOnlySpan<NativeCULong> native, ulong returned, CKM[] destination)
    {
        int available = (int)Math.Min(returned, (ulong)Math.Min(native.Length, destination.Length));
        int kept = 0;
        for (int i = 0; i < available; i++)
        {
            ulong value = (ulong)native[i];
            if (value <= uint.MaxValue)
                destination[kept++] = (CKM)value;
        }
        return kept;
    }
}
