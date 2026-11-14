using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>What a session needs to wrap a found object: its class, key type, label, id and whether it is private.</summary>
/// <param name="ObjectClass"><c>CKA_CLASS</c>.</param>
/// <param name="KeyType"><c>CKA_KEY_TYPE</c>; <see langword="default"/> when it was not asked for.</param>
/// <param name="Label"><c>CKA_LABEL</c>, UTF-8 with trailing NUL padding trimmed.</param>
/// <param name="Id"><c>CKA_ID</c>.</param>
/// <param name="IsPrivate"><c>CKA_PRIVATE</c>.</param>
internal readonly record struct ObjectIdentity(CKO ObjectClass, CKK KeyType, string Label, byte[] Id, bool IsPrivate);

/// <summary>
/// What a borrowing session (<c>Pkcs11SessionCore.Borrow</c>) reads of an object it created, when it creates it and
/// again before its return destroys it, to tell it is still that object: the module may have given a destroyed
/// object's number to another one meanwhile (PKCS#11 v3.2 allows handle reuse). Each value is <see langword="null"/>
/// when it cannot be read.
/// </summary>
/// <param name="IsToken"><c>CKA_TOKEN</c>.</param>
/// <param name="ObjectClass"><c>CKA_CLASS</c>.</param>
/// <param name="Label">
/// <c>CKA_LABEL</c>, in full, as the module returned it, however long (one longer than
/// <see cref="ObjectIdentityReader.LabelCapacity"/> is read again into a buffer of its size, so it is compared byte
/// for byte, never by length or prefix alone). Compared, never logged.
/// </param>
internal readonly record struct SessionObjectMark(bool? IsToken, CKO? ObjectClass, byte[]? Label)
{
    /// <summary>
    /// Whether <paramref name="recorded"/>, read when the object was created, still describes this one: the same
    /// class and label, each unreadable both times or equal.
    /// </summary>
    public bool Matches(SessionObjectMark recorded)
        => ObjectClass == recorded.ObjectClass
            && (Label is null ? recorded.Label is null : recorded.Label is not null && Label.AsSpan().SequenceEqual(recorded.Label));
}

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
    /// Reads <c>CKA_CLASS</c>, <c>CKA_KEY_TYPE</c> when <paramref name="withKeyType"/>, <c>CKA_LABEL</c>,
    /// <c>CKA_ID</c> and <c>CKA_PRIVATE</c> in one call.
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
        byte* isPrivate = stackalloc byte[1];
        int ulongSize = sizeof(NativeCULong);

        Span<CK_ATTRIBUTE> buffer = stackalloc CK_ATTRIBUTE[5];
        int count = 0;
        buffer[count++] = Entry(CKA.CKA_CLASS, ulongs, ulongSize);
        if (withKeyType)
            buffer[count++] = Entry(CKA.CKA_KEY_TYPE, ulongs + 1, ulongSize);
        int labelAt = count;
        buffer[count++] = Entry(CKA.CKA_LABEL, label, LabelCapacity);
        int idAt = count;
        buffer[count++] = Entry(CKA.CKA_ID, id, IdCapacity);
        int privateAt = count;
        buffer[count++] = Entry(CKA.CKA_PRIVATE, isPrivate, sizeof(byte));
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
        if ((ulong)template[privateAt].valueLen != sizeof(byte))
            return false;

        int labelLength = (int)(ulong)template[labelAt].valueLen;
        int idLength = (int)(ulong)template[idAt].valueLen;
        identity = new ObjectIdentity(
            ObjectClass: (CKO)(ulong)ulongs[0],
            KeyType: withKeyType ? (CKK)(ulong)ulongs[1] : default,
            Label: Encoding.UTF8.GetString(label, labelLength).TrimEnd('\0'),
            Id: new ReadOnlySpan<byte>(id, idLength).ToArray(),
            IsPrivate: *isPrivate != 0);
        return true;
    }

    /// <summary>
    /// Reads <c>CKA_PRIVATE</c> alone, in one call: for an object the library made or found without reading its
    /// identity (the halves of a generated pair, a key's other half).
    /// </summary>
    /// <returns>The value, or <see langword="null"/> when the read is not clean (any return value but
    /// <c>CKR_OK</c>, or a length other than one <c>CK_BBOOL</c>); the caller then decides by class.</returns>
    internal static bool? TryReadPrivate(LowLevelPkcs11Library library, NativeCULong session, NativeCULong objectId)
        => TryReadBool(library, session, objectId, CKA.CKA_PRIVATE);

    /// <summary>
    /// Reads one <c>CK_BBOOL</c> attribute of <paramref name="objectId"/>; <see langword="null"/> when it cannot be
    /// read (the object gone, the attribute absent or unreadable, a value not one byte long).
    /// </summary>
    internal static bool? TryReadBool(LowLevelPkcs11Library library, NativeCULong session, NativeCULong objectId, CKA attribute)
    {
        byte value = 0;
        Span<CK_ATTRIBUTE> template = [Entry(attribute, &value, sizeof(byte))];
        if (library.C_GetAttributeValue(session, objectId, template) != CKR.CKR_OK
            || (ulong)template[0].valueLen != sizeof(byte))
            return null;
        return value != 0;
    }

    /// <summary>
    /// Reads <c>CKA_TOKEN</c>, <c>CKA_CLASS</c> and <c>CKA_LABEL</c> of <paramref name="objectId"/> in one call, for
    /// a borrowing session's record of an object it created (<see cref="SessionObjectMark"/>). An attribute the object
    /// lacks, or will not reveal, leaves only its own value <see langword="null"/>: <c>CKR_ATTRIBUTE_TYPE_INVALID</c>,
    /// <c>CKR_ATTRIBUTE_SENSITIVE</c> and <c>CKR_BUFFER_TOO_SMALL</c> still answer every other attribute (PKCS#11 v3.2
    /// C_GetAttributeValue). Any other failure, the object gone included, leaves all three <see langword="null"/>.
    /// </summary>
    internal static SessionObjectMark ReadSessionObjectMark(LowLevelPkcs11Library library, NativeCULong session,
        NativeCULong objectId)
    {
        byte isToken = 0;
        NativeCULong objectClass = default;
        byte* label = stackalloc byte[LabelCapacity];
        int ulongSize = sizeof(NativeCULong);

        Span<CK_ATTRIBUTE> template =
        [
            Entry(CKA.CKA_TOKEN, &isToken, sizeof(byte)),
            Entry(CKA.CKA_CLASS, &objectClass, ulongSize),
            Entry(CKA.CKA_LABEL, label, LabelCapacity),
        ];

        CKR rv = library.C_GetAttributeValue(session, objectId, template);
        if (rv is not (CKR.CKR_OK or CKR.CKR_ATTRIBUTE_TYPE_INVALID or CKR.CKR_ATTRIBUTE_SENSITIVE
            or CKR.CKR_BUFFER_TOO_SMALL))
            return default;

        // CK_UNAVAILABLE_INFORMATION is all ones, so it fails every length check below as well. A label too long for
        // the stack buffer answers CKR_BUFFER_TOO_SMALL with that value (PKCS#11 v3.2 C_GetAttributeValue), and is
        // read again on its own.
        ulong labelLength = (ulong)template[2].valueLen;
        byte[]? labelValue = null;
        if (labelLength <= LabelCapacity)
            labelValue = new ReadOnlySpan<byte>(label, (int)labelLength).ToArray();
        else if (rv == CKR.CKR_BUFFER_TOO_SMALL)
            labelValue = ReadLongLabel(library, session, objectId);

        return new SessionObjectMark(
            IsToken: (ulong)template[0].valueLen == sizeof(byte) ? isToken != 0 : null,
            ObjectClass: (ulong)template[1].valueLen == (ulong)ulongSize ? (CKO)(ulong)objectClass : null,
            Label: labelValue);
    }

    /// <summary>Longest <c>CKA_LABEL</c> <see cref="ReadLongLabel"/> reads; a longer one reads as unreadable.</summary>
    internal const int LongLabelLimit = 64 * 1024;

    // CKA_LABEL alone, sized by a length query first: for a label longer than LabelCapacity. Null when either call
    // fails, the module reports more than LongLabelLimit, or the second call's length differs from the first's.
    private static byte[]? ReadLongLabel(LowLevelPkcs11Library library, NativeCULong session, NativeCULong objectId)
    {
        Span<CK_ATTRIBUTE> query = [Entry(CKA.CKA_LABEL, null, 0)];
        if (library.C_GetAttributeValue(session, objectId, query) != CKR.CKR_OK
            || (ulong)query[0].valueLen > LongLabelLimit)
            return null;

        int length = (int)(ulong)query[0].valueLen;
        byte[] value = new byte[length];
        fixed (byte* buffer = value)
        {
            query[0] = Entry(CKA.CKA_LABEL, buffer, length);
            if (library.C_GetAttributeValue(session, objectId, query) != CKR.CKR_OK
                || (ulong)query[0].valueLen != (ulong)length)
                return null;
        }
        return value;
    }

    private static CK_ATTRIBUTE Entry(CKA type, void* value, int capacity) => new()
    {
        type = type.ToCULong(),
        value = (IntPtr)value,
        valueLen = (NativeCULong)(ulong)capacity,
    };
}
