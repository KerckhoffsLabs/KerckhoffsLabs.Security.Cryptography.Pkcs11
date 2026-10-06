using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

/// <summary>
/// Lays out an attribute array (<c>CKA_WRAP_TEMPLATE</c> and friends) as one unmanaged block:
/// the <c>CK_ATTRIBUTE</c> array first, then every member's value, each member's <c>pValue</c>
/// pointing inside the block. The block has a single owner, so freeing it frees (and zeroizes) the
/// whole array, and nothing in it points at memory anyone else owns.
/// </summary>
internal static class AttributeArrayBlock
{
    // A value nested inside a value; the spec allows it, but a real template is never this deep.
    private const int MaxDepth = 4;

    /// <summary>
    /// Whether an attribute's value is an array of <c>CK_ATTRIBUTE</c>. <c>CKA_ALLOWED_MECHANISMS</c>
    /// also has the <c>CKF_ARRAY_ATTRIBUTE</c> bit, but its value is mechanism ids, not attributes.
    /// </summary>
    internal static bool IsAttributeArray(NativeCULong type)
        => (CKA)(ulong)type is CKA.CKA_WRAP_TEMPLATE or CKA.CKA_UNWRAP_TEMPLATE or CKA.CKA_DERIVE_TEMPLATE;

    /// <summary>
    /// Copies <paramref name="members"/> and the values they point at into a new block.
    /// </summary>
    /// <param name="members">The array members; their <c>pValue</c> pointers are only read.</param>
    /// <param name="arrayLength">The <c>ulValueLen</c> of the array: the size of the <c>CK_ATTRIBUTE</c>s alone.</param>
    /// <returns>The block, allocated with <see cref="UnmanagedMemory.Allocate"/>.</returns>
    internal static IntPtr Create(ReadOnlySpan<CK_ATTRIBUTE> members, out NativeCULong arrayLength)
    {
        int stride = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();
        arrayLength = (NativeCULong)(ulong)checked(stride * members.Length);

        IntPtr block = UnmanagedMemory.Allocate(Math.Max(1, Measure(members, depth: 0)));
        try
        {
            Write(members, block, start: 0, depth: 0);
            return block;
        }
        catch
        {
            UnmanagedMemory.Free(ref block);
            throw;
        }
    }

    /// <summary>Reads the members of an attribute array whose value is at <paramref name="array"/>.</summary>
    internal static CK_ATTRIBUTE[] ReadMembers(NativeCULong type, IntPtr array, NativeCULong length)
    {
        int stride = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();
        if ((ulong)length % (ulong)stride != 0)
            throw new Pkcs11AttributeException((CKA)(ulong)type);

        var members = new CK_ATTRIBUTE[checked((int)((ulong)length / (ulong)stride))];
        for (int i = 0; i < members.Length; i++)
            members[i] = UnmanagedMemory.Read<CK_ATTRIBUTE>(IntPtr.Add(array, i * stride));
        return members;
    }

    private static int Measure(ReadOnlySpan<CK_ATTRIBUTE> members, int depth)
    {
        if (depth > MaxDepth)
            throw new ArgumentException($"Attribute arrays nested more than {MaxDepth} deep.", nameof(members));

        int size = Align(checked(UnmanagedMemory.SizeOf<CK_ATTRIBUTE>() * members.Length));
        foreach (CK_ATTRIBUTE member in members)
        {
            if (!HasValue(member))
                continue;
            size = checked(size + (IsAttributeArray(member.type)
                ? Measure(ReadMembers(member.type, member.value, member.valueLen), depth + 1)
                : Align(checked((int)(ulong)member.valueLen))));
        }
        return size;
    }

    // Writes the array at block+start and the values after it; returns the end of what it wrote.
    private static int Write(ReadOnlySpan<CK_ATTRIBUTE> members, IntPtr block, int start, int depth)
    {
        int stride = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();
        int cursor = start + Align(stride * members.Length);

        for (int i = 0; i < members.Length; i++)
        {
            CK_ATTRIBUTE member = members[i];
            if (!HasValue(member))
            {
                // An unavailable (-1) or empty value carries no buffer; never keep a foreign pointer.
                member.value = IntPtr.Zero;
            }
            else if (IsAttributeArray(member.type))
            {
                CK_ATTRIBUTE[] inner = ReadMembers(member.type, member.value, member.valueLen);
                member.value = IntPtr.Add(block, cursor);
                cursor = Write(inner, block, cursor, depth + 1);
            }
            else
            {
                int length = (int)(ulong)member.valueLen;
                byte[] copy = UnmanagedMemory.Read(member.value, length);
                try
                {
                    member.value = IntPtr.Add(block, cursor);
                    UnmanagedMemory.Write(member.value, copy);
                }
                finally
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(copy);
                }
                cursor += Align(length);
            }
            UnmanagedMemory.Write(IntPtr.Add(block, start + i * stride), in member);
        }
        return cursor;
    }

    private static bool HasValue(in CK_ATTRIBUTE member)
        => member.value != IntPtr.Zero && member.valueLen != NativeCULong.MaxValue && (ulong)member.valueLen != 0;

    // Every value starts on a pointer boundary, as it would in a separately allocated buffer.
    private static int Align(int size) => checked((size + IntPtr.Size - 1) & ~(IntPtr.Size - 1));
}
