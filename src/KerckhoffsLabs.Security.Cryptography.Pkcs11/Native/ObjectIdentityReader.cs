using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>What a session needs to wrap a found object: its class, key type, label and id.</summary>
/// <param name="ObjectClass"><c>CKA_CLASS</c>.</param>
/// <param name="KeyType"><c>CKA_KEY_TYPE</c>; <see langword="default"/> when it was not asked for.</param>
/// <param name="Label"><c>CKA_LABEL</c>, UTF-8 with trailing NUL padding trimmed.</param>
/// <param name="Id"><c>CKA_ID</c>.</param>
internal readonly record struct ObjectIdentity(CKO ObjectClass, CKK KeyType, string Label, byte[] Id);

/// <summary>
/// Reads an object's <see cref="ObjectIdentity"/> in one <c>C_GetAttributeValue</c> call, into buffers
/// on the stack sized for ordinary metadata, instead of the generic reader's length query followed by
/// a read into allocated buffers. That halves the round trips per found object.
/// </summary>
/// <remarks>
/// <para>
/// The read is trusted only when it is unambiguous: the call returned <c>CKR_OK</c> and every length is
/// one the buffers could hold (the two <c>CK_ULONG</c>s exactly). Anything else returns
/// <see langword="false"/> and the caller reads again through the generic reader, which handles
/// unreadable and missing attributes, values longer than the stack buffers, and modules that report
/// lengths they did not write. A non-compliant length is a reason to fall back here, never to throw:
/// throwing would turn a module the generic reader copes with into one that cannot be enumerated.
/// </para>
/// <para>
/// Values are read from the buffers this method handed out, never from the pointers the module writes
/// back into the template, so a module cannot choose what is read. Only public metadata is requested
/// here; <c>CKA_VALUE</c> and other sensitive attributes never go through these buffers.
/// </para>
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "The module writes the attribute values through the pValue pointers in the template, so "
    + "each buffer needs a native address, and stack buffers have one only in unsafe code. The buffers "
    + "are fixed-size stackallocs owned by this frame; every reported length is checked against the "
    + "buffer's size before a byte is read, and values are read only from the buffers handed out.")]
internal static unsafe class ObjectIdentityReader
{
    /// <summary>Longest <c>CKA_LABEL</c> read in one call; a longer one falls back to the generic reader.</summary>
    internal const int LabelCapacity = 128;

    /// <summary>Longest <c>CKA_ID</c> read in one call; a longer one falls back to the generic reader.</summary>
    internal const int IdCapacity = 64;

    /// <summary>
    /// Reads <c>CKA_CLASS</c>, <c>CKA_KEY_TYPE</c> when <paramref name="withKeyType"/>, <c>CKA_LABEL</c>
    /// and <c>CKA_ID</c> in one call.
    /// </summary>
    /// <returns><see langword="true"/> with <paramref name="identity"/> set when the read is complete
    /// and unambiguous; <see langword="false"/> when the caller must read through the generic reader.</returns>
    internal static bool TryRead(LowLevelPkcs11Library library, NativeCULong session, NativeCULong objectId,
        bool withKeyType, out ObjectIdentity identity)
    {
        identity = default;

        NativeCULong* ulongs = stackalloc NativeCULong[2];
        byte* label = stackalloc byte[LabelCapacity];
        byte* id = stackalloc byte[IdCapacity];
        int ulongSize = sizeof(NativeCULong);

        Span<CK_ATTRIBUTE> buffer = stackalloc CK_ATTRIBUTE[4];
        int count = 0;
        buffer[count++] = Entry(CKA.CKA_CLASS, ulongs, ulongSize);
        if (withKeyType)
            buffer[count++] = Entry(CKA.CKA_KEY_TYPE, ulongs + 1, ulongSize);
        int labelAt = count;
        buffer[count++] = Entry(CKA.CKA_LABEL, label, LabelCapacity);
        int idAt = count;
        buffer[count++] = Entry(CKA.CKA_ID, id, IdCapacity);
        Span<CK_ATTRIBUTE> template = buffer[..count];

        if (library.C_GetAttributeValue(session, objectId, template) != CKR.CKR_OK)
            return false;

        // CK_UNAVAILABLE_INFORMATION is all ones, so it fails every capacity check below as well.
        if ((ulong)template[0].valueLen != (ulong)ulongSize)
            return false;
        if (withKeyType && (ulong)template[1].valueLen != (ulong)ulongSize)
            return false;
        if ((ulong)template[labelAt].valueLen > LabelCapacity || (ulong)template[idAt].valueLen > IdCapacity)
            return false;

        int labelLength = (int)(ulong)template[labelAt].valueLen;
        int idLength = (int)(ulong)template[idAt].valueLen;
        identity = new ObjectIdentity(
            ObjectClass: (CKO)(ulong)ulongs[0],
            KeyType: withKeyType ? (CKK)(ulong)ulongs[1] : default,
            Label: Encoding.UTF8.GetString(label, labelLength).TrimEnd('\0'),
            Id: new ReadOnlySpan<byte>(id, idLength).ToArray());
        return true;
    }

    private static CK_ATTRIBUTE Entry(CKA type, void* value, int capacity) => new()
    {
        type = type.ToCULong(),
        value = (IntPtr)value,
        valueLen = (NativeCULong)(ulong)capacity,
    };
}
