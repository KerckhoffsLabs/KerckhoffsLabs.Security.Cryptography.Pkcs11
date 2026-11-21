using System.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The bytes of a fixed-length, blank-padded PKCS#11 text field (<c>CK_UTF8CHAR</c> or <c>CK_CHAR</c> in
/// <c>CK_TOKEN_INFO</c>, <c>CK_SLOT_INFO</c>, <c>CK_INFO</c>), kept for comparisons: decoding replaces bytes that are not
/// UTF-8 with U+FFFD, so two fields that differ can decode to the same text. Compared as bytes, they never match.
/// </summary>
internal static class PaddedField
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// The field's bytes without their padding (trailing blanks and NULs), one character per byte (Latin-1), so they
    /// compare with <see cref="string.Equals(string, string, StringComparison)"/> and keep a record's value equality.
    /// </summary>
    internal static string Raw(ReadOnlySpan<byte> field)
    {
        int length = field.Length;
        while (length > 0 && field[length - 1] is (byte)' ' or 0)
            length--;
        return Encoding.Latin1.GetString(field[..length]);
    }

    /// <summary>The raw form (<see cref="Raw"/>) of <paramref name="text"/>'s UTF-8.</summary>
    /// <exception cref="EncoderFallbackException"><paramref name="text"/> has an unpaired surrogate.</exception>
    internal static string RawOf(string text) => Encoding.Latin1.GetString(StrictUtf8.GetBytes(text));

    /// <summary>Whether the raw field (<see cref="Raw"/>) is UTF-8.</summary>
    internal static bool IsUtf8(string raw)
    {
        try
        {
            StrictUtf8.GetCharCount(Encoding.Latin1.GetBytes(raw));
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }
}
