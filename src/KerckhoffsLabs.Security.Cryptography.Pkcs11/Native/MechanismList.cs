using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Converts the native <c>CK_MECHANISM_TYPE</c> list <c>C_GetMechanismList</c> fills into the
/// <see cref="CKM"/>-typed list the managed API returns.
/// </summary>
internal static class MechanismList
{
    /// <summary>
    /// Copies the entries the module returned into <paramref name="destination"/> and returns how many
    /// were copied.
    /// </summary>
    /// <remarks>
    /// Values are cast without validation, so vendor-defined mechanisms and standard ones newer than the
    /// enum survive as unnamed <see cref="CKM"/> values. <see cref="CKM"/> is as wide as the widest
    /// <c>CK_ULONG</c>, so every value is kept exactly.
    /// </remarks>
    /// <param name="native">The buffer the module filled.</param>
    /// <param name="returned">The count the module reported; entries past it (or past either buffer) are ignored.</param>
    /// <param name="destination">Receives the kept values, from index 0.</param>
    /// <returns>The number of values written to <paramref name="destination"/>.</returns>
    public static int Copy(ReadOnlySpan<NativeCULong> native, ulong returned, CKM[] destination)
    {
        int available = (int)Math.Min(returned, (ulong)Math.Min(native.Length, destination.Length));
        for (int i = 0; i < available; i++)
            destination[i] = (CKM)(ulong)native[i];
        return available;
    }
}
