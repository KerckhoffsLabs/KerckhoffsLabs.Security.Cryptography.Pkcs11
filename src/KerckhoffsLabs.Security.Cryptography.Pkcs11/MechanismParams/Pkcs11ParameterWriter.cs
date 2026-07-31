using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// Builds a vendor-defined <c>CK_*_PARAMS</c> block one field at a time. Hand it the fields in
/// declaration order and it emits the bytes the token expects, with the platform's layout rules
/// applied for you.
/// </summary>
/// <remarks>
/// <para>
/// This exists so a vendor mechanism can be used without hand-serializing a struct. The library —
/// not the caller — decides field offsets, padding, <c>CK_ULONG</c> width and pointer size, which is
/// the part that silently differs between platforms: PKCS#11 headers are packed on Windows and
/// naturally aligned elsewhere, so the same field list produces different bytes on each.
/// </para>
/// <para>
/// Every byte written lands in the operation's <c>MechanismParameterScope</c> and is released when
/// the call returns, so nothing here needs disposing and no buffer outlives the call that used it.
/// </para>
/// <para>
/// Obtained from <see cref="VendorMechanismParameters.Describe"/>; callers do not construct it.
/// </para>
/// </remarks>
public sealed class Pkcs11ParameterWriter
{
    private enum Kind { CkULong, Pointer, Byte, Inline }

    private readonly record struct Field(Kind Kind, ulong Scalar, IntPtr Pointer, byte[]? Inline);

    private readonly List<Field> _fields = [];
    private readonly MechanismParameterScope _scope;

    internal Pkcs11ParameterWriter(MechanismParameterScope scope) => _scope = scope;

    /// <summary>Appends a <c>CK_ULONG</c> field.</summary>
    /// <param name="value">Value to write.</param>
    /// <returns>This writer, for chaining.</returns>
    public Pkcs11ParameterWriter CkULong(ulong value)
    {
        _fields.Add(new Field(Kind.CkULong, value, IntPtr.Zero, null));
        return this;
    }

    /// <summary>
    /// Appends a <c>CK_OBJECT_HANDLE</c> field. Identical to <see cref="CkULong"/> on the wire; a
    /// separate method so the field list reads like the vendor's header.
    /// </summary>
    /// <param name="handle">Object handle to write.</param>
    /// <returns>This writer, for chaining.</returns>
    public Pkcs11ParameterWriter CkObjectHandle(ulong handle) => CkULong(handle);

    /// <summary>Appends a <c>CK_BBOOL</c> field (one byte, <c>0</c> or <c>1</c>).</summary>
    /// <param name="value">Value to write.</param>
    /// <returns>This writer, for chaining.</returns>
    public Pkcs11ParameterWriter CkBBool(bool value)
    {
        _fields.Add(new Field(Kind.Byte, value ? 1UL : 0UL, IntPtr.Zero, null));
        return this;
    }

    /// <summary>Appends a single raw byte field.</summary>
    /// <param name="value">Value to write.</param>
    /// <returns>This writer, for chaining.</returns>
    public Pkcs11ParameterWriter Byte(byte value)
    {
        _fields.Add(new Field(Kind.Byte, value, IntPtr.Zero, null));
        return this;
    }

    /// <summary>
    /// Appends a fixed-size inline byte array — an array embedded in the struct itself, such as the
    /// 16-byte counter block of <c>CK_AES_CTR_PARAMS</c>, not a pointer to one.
    /// </summary>
    /// <param name="value">Bytes to write. Shorter than <paramref name="length"/> is zero-padded.</param>
    /// <param name="length">Exact field width in bytes, as declared in the vendor's header.</param>
    /// <returns>This writer, for chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="length"/> is negative, or shorter than <paramref name="value"/>.</exception>
    public Pkcs11ParameterWriter InlineBytes(ReadOnlySpan<byte> value, int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(value.Length, length);

        byte[] slot = new byte[length];
        value.CopyTo(slot);
        _fields.Add(new Field(Kind.Inline, 0, IntPtr.Zero, slot));
        return this;
    }

    /// <summary>
    /// Copies <paramref name="value"/> into a separate buffer owned by the call and appends a pointer
    /// field addressing it — the <c>pFoo</c> half of the usual <c>pFoo</c>/<c>ulFooLen</c> pair. An
    /// empty span writes <c>NULL</c>, which is what PKCS#11 expects for an absent buffer.
    /// </summary>
    /// <param name="value">Bytes the token should see.</param>
    /// <returns>This writer, for chaining.</returns>
    public Pkcs11ParameterWriter Buffer(ReadOnlySpan<byte> value)
    {
        _fields.Add(new Field(Kind.Pointer, 0, _scope.Write(value), null));
        return this;
    }

    /// <summary>Appends a <c>NULL</c> pointer field.</summary>
    /// <returns>This writer, for chaining.</returns>
    public Pkcs11ParameterWriter NullPointer()
    {
        _fields.Add(new Field(Kind.Pointer, 0, IntPtr.Zero, null));
        return this;
    }

    /// <summary>
    /// Lays the accumulated fields out and writes them into the scope.
    /// </summary>
    /// <remarks>
    /// Windows PKCS#11 headers are <c>#pragma pack(1)</c>, so fields are butted together with no
    /// padding. Everywhere else each field sits at its natural alignment and the struct is rounded up
    /// to its widest member, which is what a C compiler emits for the same declaration.
    /// </remarks>
    internal Pkcs11ParameterBlock Build()
    {
        int word = UnmanagedMemory.NativeULongSize;
        int pointer = IntPtr.Size;
        bool packed = Pkcs11Marshal.IsWindows;

        int offset = 0, widest = 1;
        Span<int> offsets = _fields.Count == 0 ? [] : new int[_fields.Count];
        for (int i = 0; i < _fields.Count; i++)
        {
            (int size, int align) = _fields[i].Kind switch
            {
                Kind.CkULong => (word, word),
                Kind.Pointer => (pointer, pointer),
                Kind.Byte => (1, 1),
                _ => (_fields[i].Inline!.Length, 1),
            };
            if (!packed && align > 1)
                offset = (offset + align - 1) / align * align;
            offsets[i] = offset;
            offset += size;
            if (align > widest) widest = align;
        }

        // Trailing padding: a naturally-aligned struct is a multiple of its widest member, so an
        // array of them keeps every element aligned. Packed structs have none.
        int total = packed ? offset : (offset + widest - 1) / widest * widest;

        byte[] block = new byte[total];
        for (int i = 0; i < _fields.Count; i++)
        {
            Field f = _fields[i];
            Span<byte> slot = block.AsSpan(offsets[i]);
            switch (f.Kind)
            {
                case Kind.CkULong:
                    WriteWord(slot, f.Scalar, word);
                    break;
                case Kind.Pointer:
                    WriteWord(slot, (ulong)(long)f.Pointer, pointer);
                    break;
                case Kind.Byte:
                    slot[0] = (byte)f.Scalar;
                    break;
                default:
                    f.Inline!.CopyTo(slot);
                    break;
            }
        }

        return new Pkcs11ParameterBlock(_scope.Write(block), total);
    }

    private static void WriteWord(Span<byte> destination, ulong value, int width)
    {
        // Mask before narrowing: the assembly compiles with CheckForOverflowUnderflow, so casting a
        // shifted value straight to byte throws rather than truncating.
        // PKCS#11 blocks are consumed by the local module, so native byte order is the correct one.
        if (BitConverter.IsLittleEndian)
        {
            for (int i = 0; i < width; i++)
                destination[i] = (byte)((value >> (8 * i)) & 0xFF);
        }
        else
        {
            for (int i = 0; i < width; i++)
                destination[width - 1 - i] = (byte)((value >> (8 * i)) & 0xFF);
        }
    }
}
