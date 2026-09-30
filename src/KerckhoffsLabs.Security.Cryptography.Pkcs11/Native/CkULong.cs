using System.Runtime.CompilerServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// The one place a caller-supplied <c>CK_ULONG</c> value is narrowed to <see cref="NativeCULong"/>.
/// </summary>
/// <remarks>
/// The public surface takes <c>CK_ULONG</c> values as <see langword="ulong"/> or as the
/// <see langword="ulong"/>-backed spec enums, so every value a token can return is representable. On
/// the way back in, <c>CK_ULONG</c> is 32 bits on Windows (and on 32-bit Unix), and a wider value
/// cannot be marshalled: this refuses it with an <see cref="ArgumentOutOfRangeException"/> naming the
/// argument, instead of a bare <see cref="OverflowException"/> from a checked cast or, unchecked, a
/// silently truncated value sent to the token. Values that came back from the token (handles, session
/// ids) already fit and are converted directly.
/// </remarks>
internal static class CkULong
{
    /// <summary>Narrows <paramref name="value"/> to this platform's <c>CK_ULONG</c>.</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="value"/> is wider than <c>CK_ULONG</c> here.</exception>
    public static NativeCULong From(ulong value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        if (value > (ulong)NativeCULong.MaxValue)
            throw new ArgumentOutOfRangeException(paramName, value,
                $"0x{value:X} does not fit in CK_ULONG, which is {UnmanagedMemory.NativeULongSize * 8} bits on this platform.");
        return unchecked((NativeCULong)value);
    }
}
