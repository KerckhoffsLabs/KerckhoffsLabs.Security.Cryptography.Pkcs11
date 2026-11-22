using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>The attributes of a <see cref="KeyStrengthAttributeValues"/> the module left unanswered.</summary>
[Flags]
internal enum UnansweredAttributes
{
    None = 0,
    KeyType = 1 << 0,
    ValueLen = 1 << 1,
    ParameterSet = 1 << 2,
    HssLevels = 1 << 3,
    Modulus = 1 << 4,
    EcParams = 1 << 5,
}

/// <summary>
/// What a key's strength is judged from, as the token reported it in one call: the type and the size attributes, and
/// the <i>lengths</i> of the RSA modulus and the EC domain parameters, whose values are read by
/// <see cref="KeyStrengthAttributeReader.ReadExact"/>. Each is <see langword="null"/> when the token did not report it;
/// <paramref name="Unanswered"/> says which of those the module left unanswered (an entry it did not write), which the
/// caller asks for again alone. One the module answered as absent, sensitive or unavailable is final.
/// </summary>
/// <param name="KeyType"><c>CKA_KEY_TYPE</c>.</param>
/// <param name="ValueLen"><c>CKA_VALUE_LEN</c>.</param>
/// <param name="ParameterSet"><c>CKA_PARAMETER_SET</c>.</param>
/// <param name="HssLevels"><c>CKA_HSS_LEVELS</c>.</param>
/// <param name="ModulusLength">The length in bytes of <c>CKA_MODULUS</c> (RSA).</param>
/// <param name="EcParamsLength">The length in bytes of <c>CKA_EC_PARAMS</c> (EC).</param>
/// <param name="Unanswered">The attributes the caller must ask for again alone.</param>
internal readonly record struct KeyStrengthAttributeValues(
    ulong? KeyType, ulong? ValueLen, ulong? ParameterSet, ulong? HssLevels, int? ModulusLength, int? EcParamsLength,
    UnansweredAttributes Unanswered)
{
    /// <summary>Whether <paramref name="attribute"/> was left unanswered.</summary>
    public bool IsUnanswered(UnansweredAttributes attribute) => (Unanswered & attribute) != 0;
}

/// <summary>
/// Reads what a key's strength is judged from: in one <c>C_GetAttributeValue</c> call, the type, the size attributes
/// (<c>CKA_VALUE_LEN</c>, <c>CKA_PARAMETER_SET</c>, <c>CKA_HSS_LEVELS</c>) and the lengths of the RSA modulus and the
/// EC domain parameters; then, for an RSA or EC key, that value in a second call (<see cref="ReadExact"/>), into a
/// buffer of exactly the length the module reported. A key has the attributes its type uses; the token answers the
/// others as absent, each on its own (PKCS#11 v3.2 C_GetAttributeValue).
/// </summary>
/// <remarks>
/// <para>
/// A variable-length value is never read into a buffer that might be too small for it: some modules copy the whole value
/// whatever <c>ulValueLen</c> says (NSS softoken's <c>NSC_GetAttributeValue</c> does), which would write past the
/// buffer. So the one call asks only for the lengths (a <see langword="null"/> <c>pValue</c>, which no module writes
/// through), and <see cref="ReadExact"/> hands out a buffer of the length reported.
/// </para>
/// <para>
/// A value is trusted only when the module wrote it. A <c>CK_ULONG</c> buffer starts as
/// <c>CK_UNAVAILABLE_INFORMATION</c> and must come back exactly one <c>CK_ULONG</c> long and different; a length starts
/// as 0 and must come back between 1 and <see cref="MaxValueLength"/>. An entry left as it was handed out (a module that
/// stops at the first attribute the key lacks, which PKCS#11 does not allow) is unanswered, and the caller asks for it
/// again alone; one marked <c>CK_UNAVAILABLE_INFORMATION</c> is absent, sensitive or unavailable.
/// </para>
/// <para>
/// Values are read from the buffers this class handed out, never from the pointers the module writes back into the
/// template. Only public metadata is requested: the modulus and the domain parameters are public on every key.
/// </para>
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "The module writes the attribute values through the pValue pointers in the template, so "
    + "each buffer needs a native address, which a stack buffer or a pinned array has only in unsafe code. Every "
    + "buffer is as long as the module said its value is, every reported length is checked against the buffer's "
    + "size before a value is used, and values are read only from the buffers handed out.")]
internal static unsafe class KeyStrengthAttributeReader
{
    /// <summary>Longest modulus or domain-parameter value read: 64 KiB, far past any key's.</summary>
    internal const int MaxValueLength = 64 * 1024;

    /// <summary>Reads the type, the size attributes and the lengths of the modulus and the domain parameters, in one call.</summary>
    /// <returns>
    /// The module's return value. <c>CKR_OK</c>, <c>CKR_ATTRIBUTE_TYPE_INVALID</c>, <c>CKR_ATTRIBUTE_SENSITIVE</c>
    /// and <c>CKR_BUFFER_TOO_SMALL</c> still answer each attribute on its own; on any other, every value is
    /// <see langword="null"/> and the caller decides what the code means.
    /// </returns>
    internal static CKR Read(LowLevelPkcs11Library library, NativeCULong session, NativeCULong objectId,
        out KeyStrengthAttributeValues attributes)
    {
        attributes = default;
        int ulongSize = sizeof(NativeCULong);
        const int Ulongs = 4;
        NativeCULong* ulongs = stackalloc NativeCULong[Ulongs];
        for (int i = 0; i < Ulongs; i++)
            ulongs[i] = NativeCULong.MaxValue;

        Span<CK_ATTRIBUTE> template =
        [
            Entry(CKA.CKA_KEY_TYPE, ulongs, ulongSize),
            Entry(CKA.CKA_VALUE_LEN, ulongs + 1, ulongSize),
            Entry(CKA.CKA_PARAMETER_SET, ulongs + 2, ulongSize),
            Entry(CKA.CKA_HSS_LEVELS, ulongs + 3, ulongSize),
            // Lengths only: no buffer for a module to copy a long value into (see the remarks).
            Entry(CKA.CKA_MODULUS, null, 0),
            Entry(CKA.CKA_EC_PARAMS, null, 0),
        ];

        CKR rv = library.C_GetAttributeValue(session, objectId, template);
        if (rv is not (CKR.CKR_OK or CKR.CKR_ATTRIBUTE_TYPE_INVALID or CKR.CKR_ATTRIBUTE_SENSITIVE
            or CKR.CKR_BUFFER_TOO_SMALL))
            return rv;

        var unanswered = UnansweredAttributes.None;
        attributes = new KeyStrengthAttributeValues(
            UlongAt(template, 0, ulongs, ulongSize, UnansweredAttributes.KeyType, ref unanswered),
            UlongAt(template, 1, ulongs, ulongSize, UnansweredAttributes.ValueLen, ref unanswered),
            UlongAt(template, 2, ulongs, ulongSize, UnansweredAttributes.ParameterSet, ref unanswered),
            UlongAt(template, 3, ulongs, ulongSize, UnansweredAttributes.HssLevels, ref unanswered),
            LengthAt(template, 4, UnansweredAttributes.Modulus, ref unanswered),
            LengthAt(template, 5, UnansweredAttributes.EcParams, ref unanswered),
            unanswered);
        return rv;
    }

    /// <summary>
    /// Reads <paramref name="attribute"/> of <paramref name="objectId"/> into a buffer of exactly <paramref name="length"/>
    /// bytes, the length the module reported for it, in one call.
    /// </summary>
    /// <param name="library">The module.</param>
    /// <param name="session">The session to read through.</param>
    /// <param name="objectId">The key.</param>
    /// <param name="attribute">The byte-array attribute to read.</param>
    /// <param name="length">The length the module reported for it, 1 to <see cref="MaxValueLength"/>.</param>
    /// <param name="value">The value, or <see langword="null"/> when the module did not write exactly that many bytes.</param>
    /// <returns>The module's return value.</returns>
    internal static CKR ReadExact(LowLevelPkcs11Library library, NativeCULong session, NativeCULong objectId,
        CKA attribute, int length, out byte[]? value)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, MaxValueLength);
        value = null;
        byte[] buffer = new byte[length];
        fixed (byte* pinned = buffer)
        {
            Span<CK_ATTRIBUTE> template = [Entry(attribute, pinned, length)];
            CKR rv = library.C_GetAttributeValue(session, objectId, template);
            if (rv == CKR.CKR_OK && (ulong)template[0].valueLen == (ulong)length)
                value = buffer;
            return rv;
        }
    }

    private static ulong? UlongAt(ReadOnlySpan<CK_ATTRIBUTE> template, int index, NativeCULong* buffers, int ulongSize,
        UnansweredAttributes attribute, ref UnansweredAttributes unanswered)
    {
        if ((ulong)template[index].valueLen != (ulong)ulongSize)
            return null; // CK_UNAVAILABLE_INFORMATION, or not a CK_ULONG: answered, but not a value
        ulong value = (ulong)buffers[index];
        if (!CK.IsCkInformationUnavailable(value))
            return value;
        unanswered |= attribute; // the length and the value as handed out: the module left the entry alone
        return null;
    }

    // A length query's answer: 1 to MaxValueLength is the value's length; CK_UNAVAILABLE_INFORMATION is absent,
    // sensitive or unavailable; 0, as handed out, is an entry the module left alone. Anything else is not trusted.
    private static int? LengthAt(ReadOnlySpan<CK_ATTRIBUTE> template, int index, UnansweredAttributes attribute,
        ref UnansweredAttributes unanswered)
    {
        ulong length = (ulong)template[index].valueLen;
        if (length is > 0 and <= MaxValueLength)
            return (int)length;
        if (length == 0)
            unanswered |= attribute;
        return null;
    }

    private static CK_ATTRIBUTE Entry(CKA type, void* buffer, int length) => new()
    {
        type = (NativeCULong)(ulong)type,
        value = (IntPtr)buffer,
        valueLen = (NativeCULong)(ulong)length,
    };
}
