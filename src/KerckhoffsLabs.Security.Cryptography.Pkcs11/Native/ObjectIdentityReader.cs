using System.Runtime.InteropServices;
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
/// <c>CKA_LABEL</c>, in full, as the module returned it, up to <see cref="ObjectIdentityReader.MaxValueLength"/>, read
/// into a buffer of its reported length, so it is compared byte for byte, never by length or prefix alone. Compared,
/// never logged.
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
/// Reads an object's <see cref="ObjectIdentity"/>, and a borrowing session's <see cref="SessionObjectMark"/>, with
/// <c>C_GetAttributeValue</c> calls into buffers this class lays out, instead of the generic reader's allocated blocks.
/// </summary>
/// <remarks>
/// <para>
/// A variable-length value (<c>CKA_LABEL</c>, <c>CKA_ID</c>) is never read into a buffer that might be too short for it:
/// some modules copy the whole value whatever <c>ulValueLen</c> says (NSS softoken's <c>NSC_GetAttributeValue</c> does),
/// which would write past the buffer. So the first call reads the fixed-size attributes with the <i>lengths</i> of the
/// variable ones (a <see langword="null"/> <c>pValue</c>, which no module writes through), and a second call reads those
/// values into buffers of exactly the lengths reported; it is skipped when they are all empty.
/// </para>
/// <para>
/// The read is trusted only when it is unambiguous: every call returned <c>CKR_OK</c>, every fixed-size attribute came
/// back exactly its size, and every value came back at the length the first call reported. Anything else returns
/// <see langword="false"/> and the caller reads again through the generic reader, which handles unreadable and missing
/// attributes, and modules that report lengths they did not write. A non-compliant answer is a reason to fall back here,
/// never to throw: throwing would turn a module the generic reader copes with into one that cannot be enumerated.
/// </para>
/// <para>
/// Values are read from the buffers this class handed out, never from the pointers the module writes back into the
/// template, so a module cannot choose what is read. Only public metadata is requested here; <c>CKA_VALUE</c> and other
/// sensitive attributes never go through these buffers.
/// </para>
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "The module writes the attribute values through the pValue pointers in the template, so "
    + "each buffer needs a native address, which a stack buffer or a pinned array has only in unsafe code. Every "
    + "buffer is as long as the module said its value is, every reported length is checked against the buffer's "
    + "size before a byte is read, and values are read only from the buffers handed out.")]
internal static unsafe class ObjectIdentityReader
{
    /// <summary>Longest <c>CKA_LABEL</c> or <c>CKA_ID</c> read; a longer one falls back to the generic reader.</summary>
    internal const int MaxValueLength = 64 * 1024;

    /// <summary>
    /// Reads <c>CKA_CLASS</c>, <c>CKA_KEY_TYPE</c> when <paramref name="withKeyType"/>, <c>CKA_PRIVATE</c> and the
    /// lengths of <c>CKA_LABEL</c> and <c>CKA_ID</c> in one call; then the label and the id, at those lengths, in a
    /// second call, unless both are empty.
    /// </summary>
    /// <returns><see langword="true"/> with <paramref name="identity"/> set when the read is complete
    /// and unambiguous; <see langword="false"/> when the caller must read through the generic reader.</returns>
    internal static bool TryRead(LowLevelPkcs11Library library, NativeCULong session, NativeCULong objectId,
        bool withKeyType, out ObjectIdentity identity)
    {
        identity = default;

        NativeCULong* ulongs = stackalloc NativeCULong[2];
        byte* isPrivate = stackalloc byte[1];
        int ulongSize = sizeof(NativeCULong);

        Span<CK_ATTRIBUTE> buffer = stackalloc CK_ATTRIBUTE[5];
        int count = 0;
        buffer[count++] = Entry(CKA.CKA_CLASS, ulongs, ulongSize);
        if (withKeyType)
            buffer[count++] = Entry(CKA.CKA_KEY_TYPE, ulongs + 1, ulongSize);
        int privateAt = count;
        buffer[count++] = Entry(CKA.CKA_PRIVATE, isPrivate, sizeof(byte));
        int labelAt = count;
        buffer[count++] = Entry(CKA.CKA_LABEL, null, 0);
        int idAt = count;
        buffer[count++] = Entry(CKA.CKA_ID, null, 0);
        Span<CK_ATTRIBUTE> template = buffer[..count];

        if (library.C_GetAttributeValue(session, objectId, template) != CKR.CKR_OK)
            return false;

        // CK_UNAVAILABLE_INFORMATION is all ones, so it fails every size check below as well.
        if ((ulong)template[0].valueLen != (ulong)ulongSize)
            return false;
        if (withKeyType && (ulong)template[1].valueLen != (ulong)ulongSize)
            return false;
        if ((ulong)template[privateAt].valueLen != sizeof(byte))
            return false;
        if ((ulong)template[labelAt].valueLen > MaxValueLength || (ulong)template[idAt].valueLen > MaxValueLength)
            return false;

        byte[] label = new byte[(int)(ulong)template[labelAt].valueLen];
        byte[] id = new byte[(int)(ulong)template[idAt].valueLen];
        if (!TryReadValues(library, session, objectId, (CKA.CKA_LABEL, label), (CKA.CKA_ID, id)))
            return false;

        identity = new ObjectIdentity(
            ObjectClass: (CKO)(ulong)ulongs[0],
            KeyType: withKeyType ? (CKK)(ulong)ulongs[1] : default,
            Label: Encoding.UTF8.GetString(label).TrimEnd('\0'),
            Id: id,
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
    /// Reads <c>CKA_TOKEN</c>, <c>CKA_CLASS</c> and the length of <c>CKA_LABEL</c> of <paramref name="objectId"/> in one
    /// call, then the label at that length, for a borrowing session's record of an object it created
    /// (<see cref="SessionObjectMark"/>). An attribute the object lacks, or will not reveal, leaves only its own value
    /// <see langword="null"/>: <c>CKR_ATTRIBUTE_TYPE_INVALID</c>, <c>CKR_ATTRIBUTE_SENSITIVE</c> and
    /// <c>CKR_BUFFER_TOO_SMALL</c> still answer every other attribute (PKCS#11 v3.2 C_GetAttributeValue). Any other
    /// failure, the object gone included, leaves all three <see langword="null"/>.
    /// </summary>
    internal static SessionObjectMark ReadSessionObjectMark(LowLevelPkcs11Library library, NativeCULong session,
        NativeCULong objectId)
    {
        byte isToken = 0;
        NativeCULong objectClass = default;
        int ulongSize = sizeof(NativeCULong);

        Span<CK_ATTRIBUTE> template =
        [
            Entry(CKA.CKA_TOKEN, &isToken, sizeof(byte)),
            Entry(CKA.CKA_CLASS, &objectClass, ulongSize),
            Entry(CKA.CKA_LABEL, null, 0),
        ];

        CKR rv = library.C_GetAttributeValue(session, objectId, template);
        if (rv is not (CKR.CKR_OK or CKR.CKR_ATTRIBUTE_TYPE_INVALID or CKR.CKR_ATTRIBUTE_SENSITIVE
            or CKR.CKR_BUFFER_TOO_SMALL))
            return default;

        // CK_UNAVAILABLE_INFORMATION is all ones, so it fails the length check as well: the label reads as unreadable.
        ulong labelLength = (ulong)template[2].valueLen;
        byte[]? labelValue = null;
        if (labelLength <= MaxValueLength)
        {
            byte[] label = new byte[(int)labelLength];
            if (TryReadValues(library, session, objectId, (CKA.CKA_LABEL, label)))
                labelValue = label;
        }

        return new SessionObjectMark(
            IsToken: (ulong)template[0].valueLen == sizeof(byte) ? isToken != 0 : null,
            ObjectClass: (ulong)template[1].valueLen == (ulong)ulongSize ? (CKO)(ulong)objectClass : null,
            Label: labelValue);
    }

    // Reads each attribute into its buffer, sized to the length the module reported, in one call; true when every one
    // came back at exactly that length. An empty buffer needs no read, and when all are empty there is no call.
    private static bool TryReadValues(LowLevelPkcs11Library library, NativeCULong session, NativeCULong objectId,
        params ReadOnlySpan<(CKA Type, byte[] Buffer)> values)
    {
        Span<CK_ATTRIBUTE> template = stackalloc CK_ATTRIBUTE[values.Length];
        Span<GCHandle> pins = stackalloc GCHandle[values.Length];
        int count = 0;
        try
        {
            foreach ((CKA type, byte[] value) in values)
            {
                if (value.Length == 0)
                    continue;
                pins[count] = GCHandle.Alloc(value, GCHandleType.Pinned);
                template[count] = Entry(type, (void*)pins[count].AddrOfPinnedObject(), value.Length);
                count++;
            }
            if (count == 0)
                return true;

            Span<CK_ATTRIBUTE> read = template[..count];
            if (library.C_GetAttributeValue(session, objectId, read) != CKR.CKR_OK)
                return false;
            int i = 0;
            foreach ((CKA _, byte[] value) in values)
            {
                if (value.Length != 0 && (ulong)read[i++].valueLen != (ulong)value.Length)
                    return false;
            }
            return true;
        }
        finally
        {
            for (int i = 0; i < count; i++)
                pins[i].Free();
        }
    }

    private static CK_ATTRIBUTE Entry(CKA type, void* value, int capacity) => new()
    {
        type = type.ToCULong(),
        value = (IntPtr)value,
        valueLen = (NativeCULong)(ulong)capacity,
    };
}
