using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// Where a length or count reported by the module becomes an <see cref="int"/>. The module is outside
/// this library's control, so its answer is checked against what was actually allocated before
/// anything is sized, sliced or read from it, and a wrong answer is a <see cref="Pkcs11Exception"/>
/// rather than an <see cref="OverflowException"/>, an index out of range, or output silently
/// padded with zeros.
/// </summary>
internal static class ReportedLength
{
    /// <summary>A length the module reports before any buffer exists (a length query), as a size to allocate.</summary>
    internal static int ForAllocation(NativeCULong reported, string function)
    {
        if (reported == NativeCULong.MaxValue || (ulong)reported > (ulong)Array.MaxLength)
            throw Misreported(function, $"reported {Describe(reported)} as the length to allocate");
        return (int)(ulong)reported;
    }

    /// <summary>A length or count the module reports having written into a buffer of <paramref name="capacity"/> elements.</summary>
    internal static int Written(NativeCULong reported, int capacity, string function)
    {
        if ((ulong)reported > (ulong)capacity)
            throw Misreported(function, $"reported writing {Describe(reported)} into a buffer of {capacity}");
        return (int)(ulong)reported;
    }

    /// <summary>
    /// The bytes the module wrote: <paramref name="buffer"/> itself when it is full, otherwise a copy of
    /// the written part, with <paramref name="buffer"/> zeroized so no plaintext is left behind in it.
    /// </summary>
    internal static byte[] Trim(byte[] buffer, NativeCULong reported, string function)
    {
        int length = Written(reported, buffer.Length, function);
        if (length == buffer.Length)
            return buffer;

        byte[] written = buffer.AsSpan(0, length).ToArray();
        CryptographicOperations.ZeroMemory(buffer);
        return written;
    }

    /// <summary>The items the module wrote into <paramref name="array"/> (slot ids, mechanism types).</summary>
    internal static T[] Items<T>(T[] array, NativeCULong reported, string function)
        => array.AsSpan(0, Written(reported, array.Length, function)).ToArray();

    private static string Describe(NativeCULong reported)
        => reported == NativeCULong.MaxValue ? "CK_UNAVAILABLE_INFORMATION" : $"{(ulong)reported}";

    private static Pkcs11UnclassifiedException Misreported(string function, string what)
        => new(CKR.CKR_GENERAL_ERROR, function,
            $"The PKCS#11 module {what}. The result was refused rather than truncated or padded.");
}
