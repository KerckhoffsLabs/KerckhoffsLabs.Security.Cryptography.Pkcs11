using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

/// <summary>
/// Attribute of a cryptoki object — managed wrapper around CK_ATTRIBUTE.
/// Owns an unmanaged buffer for the value; callers MUST dispose to free it.
/// </summary>
public sealed class ObjectAttribute : IDisposable
{
    private CK_ATTRIBUTE _ckAttribute;
    private bool _disposed;

    // --- Public read surface -------------------------------------------------

    /// <summary>Attribute type (raw, e.g. 0x00000000 for CKA_CLASS).</summary>
    public ulong Type
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return (ulong)_ckAttribute.type;
        }
    }

    /// <summary>Length in bytes of the attribute's value, or 0 if no value.</summary>
    public int ValueLength
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (CannotBeRead) return 0;
            return (int)_ckAttribute.valueLen;
        }
    }

    /// <summary>
    /// True when the underlying CK_ATTRIBUTE's valueLen is the sentinel -1, indicating
    /// the module refused to disclose the attribute (sensitive/unextractable).
    /// </summary>
    public bool CannotBeRead
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            // PKCS#11 sentinel: valueLen set to the all-bits-set value of CK_ULONG
            // (uint.MaxValue on Windows, ulong.MaxValue on Linux-LP64). The module
            // uses this to signal that the attribute is sensitive or unextractable.
            // NativeCULong.MaxValue is exactly that on both platforms.
            return _ckAttribute.valueLen == NativeCULong.MaxValue;
        }
    }

    // --- Marshalling adapter (internal-only; not exposed publicly) ----------

    internal CK_ATTRIBUTE CkAttribute
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _ckAttribute;
        }
    }

    // --- Constructors --------------------------------------------------------

    /// <summary>Wraps an existing low-level CK_ATTRIBUTE struct. The instance takes ownership of any unmanaged buffer the struct points at and frees it on <see cref="Dispose"/>.</summary>
    internal ObjectAttribute(CK_ATTRIBUTE attribute)
    {
        _ckAttribute = attribute;
    }

    /// <summary>Creates an attribute of the given vendor-defined attribute id with no value.</summary>
    public ObjectAttribute(ulong type) { _ckAttribute = _CreateAttribute((NativeCULong)type, ReadOnlySpan<byte>.Empty); }
    /// <summary>Creates an attribute of the given <see cref="CKA"/> type with no value.</summary>
    public ObjectAttribute(CKA type) : this((ulong)type) { }

    /// <summary>Creates a vendor-defined-id attribute holding a <see cref="ulong"/> value (encoded as CK_ULONG on the wire).</summary>
    public ObjectAttribute(ulong type, ulong value)
    {
        Span<byte> buf = stackalloc byte[sizeof(ulong)];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(buf, value);
        _ckAttribute = _CreateAttribute((NativeCULong)type, buf[..UnmanagedMemory.NativeULongSize]);
    }
    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a <see cref="ulong"/> value (encoded as CK_ULONG on the wire).</summary>
    public ObjectAttribute(CKA type, ulong value) : this((ulong)type, value) { }
    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a <see cref="CKC"/> enum value.</summary>
    public ObjectAttribute(CKA type, CKC value) : this((ulong)type, (ulong)value) { }
    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a <see cref="CKK"/> enum value.</summary>
    public ObjectAttribute(CKA type, CKK value) : this((ulong)type, (ulong)value) { }
    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a <see cref="CKO"/> enum value.</summary>
    public ObjectAttribute(CKA type, CKO value) : this((ulong)type, (ulong)value) { }

    /// <summary>Creates a vendor-defined-id attribute holding a bool value (encoded as a single byte: 0x01 or 0x00).</summary>
    public ObjectAttribute(ulong type, bool value)
    {
        Span<byte> buf = stackalloc byte[1];
        buf[0] = value ? (byte)0x01 : (byte)0x00;
        _ckAttribute = _CreateAttribute((NativeCULong)type, buf);
    }
    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a bool value (encoded as a single byte: 0x01 or 0x00).</summary>
    public ObjectAttribute(CKA type, bool value) : this((ulong)type, value) { }

    /// <summary>Creates a vendor-defined-id attribute holding a UTF-8 string with no null terminator.</summary>
    public ObjectAttribute(ulong type, string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        ReadOnlySpan<byte> bytes = System.Text.Encoding.UTF8.GetBytes(value); // no null terminator
        _ckAttribute = _CreateAttribute((NativeCULong)type, bytes);
    }
    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a UTF-8 string with no null terminator.</summary>
    public ObjectAttribute(CKA type, string value) : this((ulong)type, value) { }

    /// <summary>Creates a vendor-defined-id attribute holding the bytes of <paramref name="value"/>.</summary>
    public ObjectAttribute(ulong type, byte[] value)
        : this(type, (ReadOnlySpan<byte>)(value ?? Array.Empty<byte>())) { }
    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding the bytes of <paramref name="value"/>.</summary>
    public ObjectAttribute(CKA type, byte[] value) : this((ulong)type, value) { }

    /// <summary>Creates a vendor-defined-id attribute holding the bytes of <paramref name="value"/>. Zero-allocation when the caller already holds a span.</summary>
    public ObjectAttribute(ulong type, ReadOnlySpan<byte> value)
    {
        _ckAttribute = _CreateAttribute((NativeCULong)type, value);
    }
    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding the bytes of <paramref name="value"/>. Zero-allocation when the caller already holds a span.</summary>
    public ObjectAttribute(CKA type, ReadOnlySpan<byte> value) : this((ulong)type, value) { }

    /// <summary>Creates a vendor-defined-id attribute holding a date value (encoded as 8-byte ASCII "yyyyMMdd").</summary>
    public ObjectAttribute(ulong type, DateTime value)
    {
        // CK_DATE wire format: 8 ASCII bytes "YYYYMMDD"
        string formatted = value.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture);
        ReadOnlySpan<byte> bytes = System.Text.Encoding.ASCII.GetBytes(formatted);
        _ckAttribute = _CreateAttribute((NativeCULong)type, bytes);
    }
    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a date value (encoded as 8-byte ASCII "yyyyMMdd").</summary>
    public ObjectAttribute(CKA type, DateTime value) : this((ulong)type, value) { }

    /// <summary>Creates a vendor-defined-id attribute holding a list of nested attributes (encoded as a contiguous CK_ATTRIBUTE[] in unmanaged memory).</summary>
    public ObjectAttribute(ulong type, List<ObjectAttribute> value)
    {
        ArgumentNullException.ThrowIfNull(value);
        int stride = UnmanagedMemory.SizeOf(typeof(CK_ATTRIBUTE));
        byte[] flat = new byte[stride * value.Count];
        // Marshal each child's CK_ATTRIBUTE into the flat buffer.
        unsafe
        {
            fixed (byte* p = flat)
            {
                IntPtr basePtr = (IntPtr)p;
                for (int i = 0; i < value.Count; i++)
                {
                    IntPtr slot = new IntPtr(basePtr.ToInt64() + (long)i * stride);
                    UnmanagedMemory.Write(slot, value[i]._ckAttribute);
                }
            }
        }
        _ckAttribute = _CreateAttribute((NativeCULong)type, flat);
    }
    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a list of nested attributes (encoded as a contiguous CK_ATTRIBUTE[] in unmanaged memory).</summary>
    public ObjectAttribute(CKA type, List<ObjectAttribute> value) : this((ulong)type, value) { }

    /// <summary>Creates a vendor-defined-id attribute holding a list of <see cref="ulong"/> values (encoded as a contiguous CK_ULONG[] in unmanaged memory).</summary>
    public ObjectAttribute(ulong type, List<ulong> value)
    {
        ArgumentNullException.ThrowIfNull(value);
        int stride = UnmanagedMemory.NativeULongSize;
        byte[] flat = new byte[stride * value.Count];
        Span<byte> dest = flat;
        for (int i = 0; i < value.Count; i++)
        {
            // PKCS#11 uses CK_ULONG (NativeCULong) for these lists — 4 bytes on Windows, 8 on Unix-x64.
            // We always write the low 32 bits little-endian when stride==4, otherwise 64 bits.
            if (stride == 4)
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(dest.Slice(i * stride, 4), checked((uint)value[i]));
            else
                System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(dest.Slice(i * stride, 8), value[i]);
        }
        _ckAttribute = _CreateAttribute((NativeCULong)type, flat);
    }
    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a list of <see cref="ulong"/> values (encoded as a contiguous CK_ULONG[] in unmanaged memory).</summary>
    public ObjectAttribute(CKA type, List<ulong> value) : this((ulong)type, value) { }

    /// <summary>Creates a vendor-defined-id attribute holding a list of <see cref="CKM"/> values (encoded as a contiguous CK_ULONG[] in unmanaged memory).</summary>
    public ObjectAttribute(ulong type, List<CKM> value)
    {
        ArgumentNullException.ThrowIfNull(value);
        // Reuse the List<ulong> path after converting each CKM.
        List<ulong> ulist = new(value.Count);
        for (int i = 0; i < value.Count; i++)
            ulist.Add((ulong)value[i]);
        // Inline rather than `this(type, ulist)` so we only allocate the native buffer once.
        int stride = UnmanagedMemory.NativeULongSize;
        byte[] flat = new byte[stride * ulist.Count];
        Span<byte> dest = flat;
        for (int i = 0; i < ulist.Count; i++)
        {
            if (stride == 4)
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(dest.Slice(i * stride, 4), checked((uint)ulist[i]));
            else
                System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(dest.Slice(i * stride, 8), ulist[i]);
        }
        _ckAttribute = _CreateAttribute((NativeCULong)type, flat);
    }
    /// <summary>Creates a <see cref="CKA"/>-typed attribute holding a list of <see cref="CKM"/> values (encoded as a contiguous CK_ULONG[] in unmanaged memory).</summary>
    public ObjectAttribute(CKA type, List<CKM> value) : this((ulong)type, value) { }

    // --- Read-back -----------------------------------------------------------

    public bool GetValueAsBool()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException(Type);
        if ((int)_ckAttribute.valueLen != 1)
            throw new AttributeValueException(Type);
        byte b = Marshal.ReadByte(_ckAttribute.value);
        return b != 0;
    }

    public ulong GetValueAsUlong()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException(Type);
        int len = (int)_ckAttribute.valueLen;
        if (len != UnmanagedMemory.NativeULongSize)
            throw new AttributeValueException(Type);
        Span<byte> tmp = stackalloc byte[8];
        UnmanagedMemory.Read(_ckAttribute.value, tmp[..len]);
        return len == 4
            ? System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(tmp[..4])
            : System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(tmp[..8]);
    }

    public string GetValueAsString()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException(Type);
        int len = (int)_ckAttribute.valueLen;
        if (len == 0) return string.Empty;
        byte[] buf = new byte[len];
        UnmanagedMemory.Read(_ckAttribute.value, buf);
        return System.Text.Encoding.UTF8.GetString(buf).TrimEnd('\0');
    }

    public byte[] GetValueAsByteArray()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException(Type);
        int len = (int)_ckAttribute.valueLen;
        byte[] buf = new byte[len];
        if (len > 0) UnmanagedMemory.Read(_ckAttribute.value, buf);
        return buf;
    }

    /// <summary>
    /// Copies the attribute's raw value bytes into <paramref name="destination"/>. Returns the
    /// number of bytes written. Allocates nothing. Use <see cref="ValueLength"/> to size the
    /// destination buffer.
    /// </summary>
    /// <exception cref="ArgumentException">if <paramref name="destination"/> is too small.</exception>
    public int CopyValueTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException(Type);
        int len = (int)_ckAttribute.valueLen;
        if (destination.Length < len)
            throw new ArgumentException($"Destination too small: needs {len} bytes, got {destination.Length}.", nameof(destination));
        if (len > 0) UnmanagedMemory.Read(_ckAttribute.value, destination[..len]);
        return len;
    }

    public DateTime? GetValueAsDateTime()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException(Type);
        int len = (int)_ckAttribute.valueLen;
        if (len == 0) return null;
        if (len != 8) throw new AttributeValueException(Type);
        byte[] buf = new byte[8];
        UnmanagedMemory.Read(_ckAttribute.value, buf);
        string s = System.Text.Encoding.ASCII.GetString(buf);
        if (!DateTime.TryParseExact(s, "yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture,
                                    System.Globalization.DateTimeStyles.None, out DateTime dt))
        {
            return null;
        }
        return DateTime.SpecifyKind(dt, DateTimeKind.Utc);
    }

    public ObjectAttribute[] GetValueAsAttributeArray()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException(Type);
        int total = (int)_ckAttribute.valueLen;
        int stride = UnmanagedMemory.SizeOf(typeof(CK_ATTRIBUTE));
        int n = total / stride;
        if (total % stride != 0)
            throw new AttributeValueException(Type);
        ObjectAttribute[] result = new ObjectAttribute[n];
        for (int i = 0; i < n; i++)
        {
            IntPtr slot = new IntPtr(_ckAttribute.value.ToInt64() + (long)i * stride);
            CK_ATTRIBUTE attr = (CK_ATTRIBUTE)UnmanagedMemory.Read(slot, typeof(CK_ATTRIBUTE))!;
            result[i] = new ObjectAttribute(attr);
        }
        return result;
    }

    public ulong[] GetValueAsUlongArray()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new AttributeValueException(Type);
        int stride = UnmanagedMemory.NativeULongSize;
        int total = (int)_ckAttribute.valueLen;
        int n = total / stride;
        if (total % stride != 0)
            throw new AttributeValueException(Type);
        ulong[] result = new ulong[n];
        byte[] buf = new byte[total];
        if (total > 0) UnmanagedMemory.Read(_ckAttribute.value, buf);
        for (int i = 0; i < n; i++)
        {
            ReadOnlySpan<byte> slice = buf.AsSpan(i * stride, stride);
            result[i] = stride == 4
                ? System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(slice)
                : System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(slice);
        }
        return result;
    }

    public CKM[] GetValueAsCkmArray()
    {
        ulong[] raw = GetValueAsUlongArray();
        CKM[] result = new CKM[raw.Length];
        for (int i = 0; i < raw.Length; i++) result[i] = (CKM)raw[i];
        return result;
    }

    // --- IDisposable ---------------------------------------------------------

    public void Dispose()
    {
        if (_disposed) return;
        if (_ckAttribute.value != IntPtr.Zero)
        {
            UnmanagedMemory.Free(ref _ckAttribute.value);
        }
        _ckAttribute.valueLen = (NativeCULong)0;
        _disposed = true;
    }

    // --- Private marshalling kernel ------------------------------------------

    private static CK_ATTRIBUTE _CreateAttribute(NativeCULong type, ReadOnlySpan<byte> value)
    {
        CK_ATTRIBUTE a = new CK_ATTRIBUTE { type = type };
        if (value.Length > 0)
        {
            a.value = UnmanagedMemory.Allocate(value.Length);
            UnmanagedMemory.Write(a.value, value);
            a.valueLen = (NativeCULong)value.Length;
        }
        else
        {
            a.value = IntPtr.Zero;
            a.valueLen = (NativeCULong)0;
        }
        return a;
    }
}
