using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Reads <c>CK_ULONG</c> attributes of an object in one <c>C_GetAttributeValue</c> call, into buffers on the stack
/// sized for a <c>CK_ULONG</c>, instead of the generic reader's length query followed by a read into allocated
/// buffers.
/// </summary>
/// <remarks>
/// <para>
/// A value is trusted only when the module wrote it: the length it reports is exactly one <c>CK_ULONG</c>, and the
/// value is not <c>CK_UNAVAILABLE_INFORMATION</c>. Each buffer starts as <c>CK_UNAVAILABLE_INFORMATION</c>, so an
/// entry a module leaves untouched (one that stops at the first attribute the object lacks, which PKCS#11 v3.2
/// C_GetAttributeValue does not allow) reads as not reported, never as zero.
/// </para>
/// <para>
/// Values are read from the buffers this method handed out, never from the pointers the module writes back into the
/// template, so a module cannot choose what is read. Only public metadata is requested here.
/// </para>
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "The module writes the attribute values through the pValue pointers in the template, so "
    + "each buffer needs a native address, and stack buffers have one only in unsafe code. The buffers "
    + "are fixed-size stackallocs owned by this frame; every reported length is checked against the "
    + "buffer's size before a value is used, and values are read only from the buffers handed out.")]
internal static unsafe class UlongAttributeReader
{
    /// <summary>Most attributes one call reads.</summary>
    internal const int MaxAttributes = 8;

    /// <summary>
    /// Reads <paramref name="types"/> of <paramref name="objectId"/> in one call, each value into
    /// <paramref name="values"/> at the same index: the value, or <see langword="null"/> when the module did not
    /// report one (the attribute absent, sensitive, not one <c>CK_ULONG</c> long, or
    /// <c>CK_UNAVAILABLE_INFORMATION</c>).
    /// </summary>
    /// <returns>
    /// The module's return value. <c>CKR_OK</c>, <c>CKR_ATTRIBUTE_TYPE_INVALID</c>, <c>CKR_ATTRIBUTE_SENSITIVE</c>
    /// and <c>CKR_BUFFER_TOO_SMALL</c> still answer each attribute on its own (PKCS#11 v3.2 C_GetAttributeValue); on
    /// any other, every value is <see langword="null"/> and the caller decides what the code means.
    /// </returns>
    /// <exception cref="ArgumentException"><paramref name="values"/> is not as long as <paramref name="types"/>, or
    /// more than <see cref="MaxAttributes"/> are asked for.</exception>
    internal static CKR Read(LowLevelPkcs11Library library, NativeCULong session, NativeCULong objectId,
        ReadOnlySpan<CKA> types, Span<ulong?> values)
    {
        if (values.Length != types.Length || types.Length is 0 or > MaxAttributes)
            throw new ArgumentException($"Between 1 and {MaxAttributes} attributes, with one value slot each.", nameof(types));

        int ulongSize = sizeof(NativeCULong);
        NativeCULong* buffers = stackalloc NativeCULong[MaxAttributes];
        Span<CK_ATTRIBUTE> template = stackalloc CK_ATTRIBUTE[types.Length];
        for (int i = 0; i < types.Length; i++)
        {
            buffers[i] = NativeCULong.MaxValue;
            template[i] = new CK_ATTRIBUTE
            {
                type = (NativeCULong)(ulong)types[i],
                value = (IntPtr)(buffers + i),
                valueLen = (NativeCULong)(ulong)ulongSize,
            };
        }

        values.Clear();
        CKR rv = library.C_GetAttributeValue(session, objectId, template);
        if (rv is not (CKR.CKR_OK or CKR.CKR_ATTRIBUTE_TYPE_INVALID or CKR.CKR_ATTRIBUTE_SENSITIVE
            or CKR.CKR_BUFFER_TOO_SMALL))
            return rv;

        for (int i = 0; i < types.Length; i++)
        {
            if ((ulong)template[i].valueLen != (ulong)ulongSize)
                continue;
            ulong value = (ulong)buffers[i];
            values[i] = CK.IsCkInformationUnavailable(value) ? null : value;
        }
        return rv;
    }
}
