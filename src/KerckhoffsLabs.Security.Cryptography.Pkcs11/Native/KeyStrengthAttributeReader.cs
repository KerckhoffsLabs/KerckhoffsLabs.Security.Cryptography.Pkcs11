using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>Which attribute of a <see cref="KeyStrengthAttributeValues"/> the module left unanswered.</summary>
[Flags]
internal enum KeyStrengthAttribute
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
/// What a key's strength is judged from, as the token reported it. Each value is <see langword="null"/> when the token
/// did not report it; <paramref name="Unanswered"/> says which of those the module left unanswered (an entry it did not
/// write, or a value too long for the buffer), which the caller asks for again alone. One the module answered as absent,
/// sensitive or unavailable is final.
/// </summary>
/// <param name="KeyType"><c>CKA_KEY_TYPE</c>.</param>
/// <param name="ValueLen"><c>CKA_VALUE_LEN</c>.</param>
/// <param name="ParameterSet"><c>CKA_PARAMETER_SET</c>.</param>
/// <param name="HssLevels"><c>CKA_HSS_LEVELS</c>.</param>
/// <param name="Modulus"><c>CKA_MODULUS</c> (RSA), big-endian.</param>
/// <param name="EcParams"><c>CKA_EC_PARAMS</c> (EC), DER.</param>
/// <param name="Unanswered">The attributes the caller must ask for again alone.</param>
internal readonly record struct KeyStrengthAttributeValues(
    ulong? KeyType, ulong? ValueLen, ulong? ParameterSet, ulong? HssLevels, byte[]? Modulus, byte[]? EcParams,
    KeyStrengthAttribute Unanswered)
{
    /// <summary>Whether <paramref name="attribute"/> was left unanswered.</summary>
    public bool IsUnanswered(KeyStrengthAttribute attribute) => (Unanswered & attribute) != 0;
}

/// <summary>
/// Reads, in one <c>C_GetAttributeValue</c> call into stack buffers, every attribute a key's strength is judged
/// from: the type, the size attributes (<c>CKA_VALUE_LEN</c>, <c>CKA_PARAMETER_SET</c>, <c>CKA_HSS_LEVELS</c>), the
/// RSA modulus and the EC domain parameters. A key has the ones its type uses; the token answers the others as absent,
/// each on its own (PKCS#11 v3.2 C_GetAttributeValue).
/// </summary>
/// <remarks>
/// <para>
/// A value is trusted only when the module wrote it. A <c>CK_ULONG</c> buffer starts as
/// <c>CK_UNAVAILABLE_INFORMATION</c> and must come back exactly one <c>CK_ULONG</c> long and different. A byte-array
/// buffer is handed out one byte longer than any value this reader trusts, and must come back shorter than that.
/// </para>
/// <para>
/// An entry the module left as it was handed out (one that stops at the first attribute the key lacks, which PKCS#11
/// does not allow) is <i>unanswered</i>, not absent, and so is a byte array the module could not fit
/// (<c>CKR_BUFFER_TOO_SMALL</c> marks it <c>CK_UNAVAILABLE_INFORMATION</c>, as it marks an absent one): the caller asks
/// for it again alone. An entry the module marked <c>CK_UNAVAILABLE_INFORMATION</c> otherwise is answered: absent,
/// sensitive or unavailable.
/// </para>
/// <para>
/// Values are read from the buffers this method handed out, never from the pointers the module writes back into the
/// template. Only public metadata is requested: the modulus and the domain parameters are public on every key.
/// </para>
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "The module writes the attribute values through the pValue pointers in the template, so "
    + "each buffer needs a native address, and stack buffers have one only in unsafe code. The buffers "
    + "are fixed-size stackallocs owned by this frame; every reported length is checked against the "
    + "buffer's size before a byte is read, and values are read only from the buffers handed out.")]
internal static unsafe class KeyStrengthAttributeReader
{
    /// <summary>Longest <c>CKA_MODULUS</c> read in one call: 8192 bits. A longer one is read on its own.</summary>
    internal const int ModulusCapacity = 1024;

    /// <summary>Longest <c>CKA_EC_PARAMS</c> read in one call. A named curve's OID is far shorter.</summary>
    internal const int EcParamsCapacity = 128;

    /// <summary>Reads the attributes a key's strength is judged from, in one call.</summary>
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
        // One byte past each capacity: a value that fills the whole buffer is never trusted (see the remarks).
        byte* modulus = stackalloc byte[ModulusCapacity + 1];
        byte* ecParams = stackalloc byte[EcParamsCapacity + 1];

        Span<CK_ATTRIBUTE> template =
        [
            Entry(CKA.CKA_KEY_TYPE, ulongs, ulongSize),
            Entry(CKA.CKA_VALUE_LEN, ulongs + 1, ulongSize),
            Entry(CKA.CKA_PARAMETER_SET, ulongs + 2, ulongSize),
            Entry(CKA.CKA_HSS_LEVELS, ulongs + 3, ulongSize),
            Entry(CKA.CKA_MODULUS, modulus, ModulusCapacity + 1),
            Entry(CKA.CKA_EC_PARAMS, ecParams, EcParamsCapacity + 1),
        ];

        CKR rv = library.C_GetAttributeValue(session, objectId, template);
        if (rv is not (CKR.CKR_OK or CKR.CKR_ATTRIBUTE_TYPE_INVALID or CKR.CKR_ATTRIBUTE_SENSITIVE
            or CKR.CKR_BUFFER_TOO_SMALL))
            return rv;

        bool tooSmallPossible = rv == CKR.CKR_BUFFER_TOO_SMALL;
        var unanswered = KeyStrengthAttribute.None;
        ulong? keyType = UlongAt(template, 0, ulongs, ulongSize, KeyStrengthAttribute.KeyType, ref unanswered);
        ulong? valueLen = UlongAt(template, 1, ulongs, ulongSize, KeyStrengthAttribute.ValueLen, ref unanswered);
        ulong? parameterSet = UlongAt(template, 2, ulongs, ulongSize, KeyStrengthAttribute.ParameterSet, ref unanswered);
        ulong? hssLevels = UlongAt(template, 3, ulongs, ulongSize, KeyStrengthAttribute.HssLevels, ref unanswered);
        byte[]? modulusValue = BytesAt(template, 4, modulus, ModulusCapacity, tooSmallPossible, KeyStrengthAttribute.Modulus, ref unanswered);
        byte[]? ecParamsValue = BytesAt(template, 5, ecParams, EcParamsCapacity, tooSmallPossible, KeyStrengthAttribute.EcParams, ref unanswered);

        attributes = new KeyStrengthAttributeValues(keyType, valueLen, parameterSet, hssLevels, modulusValue, ecParamsValue, unanswered);
        return rv;
    }

    private static ulong? UlongAt(ReadOnlySpan<CK_ATTRIBUTE> template, int index, NativeCULong* buffers, int ulongSize,
        KeyStrengthAttribute attribute, ref KeyStrengthAttribute unanswered)
    {
        if ((ulong)template[index].valueLen != (ulong)ulongSize)
            return null; // CK_UNAVAILABLE_INFORMATION, or not a CK_ULONG: answered, but not a value
        ulong value = (ulong)buffers[index];
        if (!CK.IsCkInformationUnavailable(value))
            return value;
        unanswered |= attribute; // the length and the value as handed out: the module left the entry alone
        return null;
    }

    private static byte[]? BytesAt(ReadOnlySpan<CK_ATTRIBUTE> template, int index, byte* buffer, int capacity,
        bool tooSmallPossible, KeyStrengthAttribute attribute, ref KeyStrengthAttribute unanswered)
    {
        ulong length = (ulong)template[index].valueLen;
        if (length > 0 && length <= (ulong)capacity)
            return new ReadOnlySpan<byte>(buffer, (int)length).ToArray();
        // Untouched (the full length handed out), or possibly too long for the buffer under CKR_BUFFER_TOO_SMALL.
        if (length == (ulong)capacity + 1 || (tooSmallPossible && CK.IsCkInformationUnavailable(length)))
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
