using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.InteropServices;
using System.Text;
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
    private volatile bool _disposed;

    /// <summary>
    /// Whether this instance owns the unmanaged buffer <c>_ckAttribute.value</c> points at, and so
    /// must free it. False for the read-only views <see cref="GetValueAsAttributeArray"/> hands back:
    /// those point into buffers a nested template's children own, and freeing one from here would
    /// release memory still described by a live attribute somewhere else.
    /// </summary>
    /// <remarks>Defaults to <c>true</c>: every value-constructing overload allocates its own buffer.
    /// Only the explicit view constructor opts out.</remarks>
    private readonly bool _ownsValue = true;

    /// <summary>
    /// Set once, atomically, by whichever of <see cref="Dispose()"/> or the finalizer arrives first.
    /// <c>UnmanagedMemory.Free</c> throws on a second free, and a throw on the finalizer thread is
    /// fatal to the process, so the claim has to be atomic rather than a plain flag test.
    /// </summary>
    private int _releaseClaimed;

    // --- Public read surface -------------------------------------------------

    /// <summary>
    /// Attribute type. A vendor-defined or newer-than-this-library type names no <see cref="CKA"/>
    /// member but is carried exactly.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the attribute has been disposed.</exception>
    public CKA Type
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return (CKA)(ulong)_ckAttribute.type;
        }
    }

    /// <summary>Length in bytes of the attribute's value, or 0 if no value.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the attribute has been disposed.</exception>
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
    /// <exception cref="ObjectDisposedException">Thrown if the attribute has been disposed.</exception>
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
    internal ObjectAttribute(CK_ATTRIBUTE attribute) : this(attribute, ownsValue: true) { }

    /// <summary>
    /// Wraps an existing low-level CK_ATTRIBUTE struct, stating explicitly whether this instance
    /// owns the buffer it points at. A non-owning instance is a read-only view: it never frees, and
    /// it suppresses its own finalizer, because the memory belongs to someone still using it.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3971:Do not call 'GC.SuppressFinalize'",
        Justification = "The rule guards against suppressing finalization outside Dispose to paper over a " +
        "finalization bug. Here it states a fact fixed at construction: a non-owning view has no cleanup " +
        "obligation for the whole of its life, so it has no reason to sit on the finalization queue. " +
        "Correctness does not depend on it — Release() is already a no-op when _ownsValue is false — so this " +
        "only keeps the read-only views GetValueAsAttributeArray hands back, which are created in bulk and " +
        "die immediately, from being promoted for a finalizer that would do nothing.")]
    internal ObjectAttribute(CK_ATTRIBUTE attribute, bool ownsValue)
    {
        _ckAttribute = attribute;
        _ownsValue = ownsValue;
        if (!ownsValue)
            GC.SuppressFinalize(this);
    }

    // One constructor per value shape. A vendor-defined attribute is a CKA value too: CKA is ulong-backed
    // like CK_ATTRIBUTE_TYPE, so (CKA)0x80000123 names it without loss. Every constructor refuses, with
    // ArgumentOutOfRangeException, a type or CK_ULONG value wider than this platform's CK_ULONG (32 bits
    // on Windows) instead of truncating it.

    /// <summary>Creates an attribute of the given type with no value.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> is wider than this platform's <c>CK_ULONG</c>.</exception>
    public ObjectAttribute(CKA type) { _ckAttribute = CreateAttribute(type.ToCULong(), []); }

    /// <summary>Creates an attribute holding a <c>CK_ULONG</c> value.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> or <paramref name="value"/> is wider than this platform's <c>CK_ULONG</c>.</exception>
    public ObjectAttribute(CKA type, ulong value)
    {
        Span<byte> buf = stackalloc byte[UnmanagedMemory.NativeULongSize];
        WriteCULong(buf, value, nameof(value));
        _ckAttribute = CreateAttribute(type.ToCULong(), buf);
    }
    /// <summary>Creates an attribute holding a <see cref="CKC"/> value.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> or <paramref name="value"/> is wider than this platform's <c>CK_ULONG</c>.</exception>
    public ObjectAttribute(CKA type, CKC value) : this(type, (ulong)value) { }
    /// <summary>Creates an attribute holding a <see cref="CKK"/> value.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> or <paramref name="value"/> is wider than this platform's <c>CK_ULONG</c>.</exception>
    public ObjectAttribute(CKA type, CKK value) : this(type, (ulong)value) { }
    /// <summary>Creates an attribute holding a <see cref="CKO"/> value.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> or <paramref name="value"/> is wider than this platform's <c>CK_ULONG</c>.</exception>
    public ObjectAttribute(CKA type, CKO value) : this(type, (ulong)value) { }

    /// <summary>Creates an attribute holding a bool value (encoded as a single byte: 0x01 or 0x00).</summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> is wider than this platform's <c>CK_ULONG</c>.</exception>
    public ObjectAttribute(CKA type, bool value)
    {
        Span<byte> buf = [value ? (byte)0x01 : (byte)0x00];
        _ckAttribute = CreateAttribute(type.ToCULong(), buf);
    }

    /// <summary>Creates an attribute holding a UTF-8 string with no null terminator.</summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> is wider than this platform's <c>CK_ULONG</c>.</exception>
    public ObjectAttribute(CKA type, string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        ReadOnlySpan<byte> bytes = Encoding.UTF8.GetBytes(value); // no null terminator
        _ckAttribute = CreateAttribute(type.ToCULong(), bytes);
    }

    /// <summary>
    /// Creates an attribute holding the bytes of <paramref name="value"/>. A <c>byte[]</c> converts to the
    /// span implicitly; a <see langword="null"/> array is an empty value.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> is wider than this platform's <c>CK_ULONG</c>.</exception>
    public ObjectAttribute(CKA type, ReadOnlySpan<byte> value)
    {
        _ckAttribute = CreateAttribute(type.ToCULong(), value);
    }

    /// <summary>Creates an attribute holding a date value (encoded as 8-byte ASCII "yyyyMMdd").</summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> is wider than this platform's <c>CK_ULONG</c>.</exception>
    public ObjectAttribute(CKA type, DateTime value)
    {
        // CK_DATE wire format: 8 ASCII bytes "YYYYMMDD"
        string formatted = value.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture);
        ReadOnlySpan<byte> bytes = Encoding.ASCII.GetBytes(formatted);
        _ckAttribute = CreateAttribute(type.ToCULong(), bytes);
    }

    /// <summary>Creates an attribute holding a list of nested attributes (encoded as a contiguous CK_ATTRIBUTE[] in unmanaged memory).</summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> is wider than this platform's <c>CK_ULONG</c>.</exception>
    public ObjectAttribute(CKA type, IReadOnlyList<ObjectAttribute> value)
    {
        ArgumentNullException.ThrowIfNull(value);
        NativeCULong nativeType = type.ToCULong();
        int stride = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();
        byte[] flat = new byte[stride * value.Count];
        if (value.Count > 0)
        {
            // Marshal each child's CK_ATTRIBUTE (platform-correct, packed-aware layout) into an
            // unmanaged scratch block, then copy it back into the managed flat buffer. Going through
            // the UnmanagedMemory helpers keeps the pinning/pointer work — and the only `unsafe` — in
            // the Native layer rather than here.
            IntPtr scratch = UnmanagedMemory.Allocate(stride * value.Count);
            try
            {
                for (int i = 0; i < value.Count; i++)
                {
                    // Read through CkAttribute, not the field: a disposed child would otherwise be
                    // copied verbatim as {type, NULL, 0} — an attribute that is present but empty,
                    // which in a CKA_WRAP_TEMPLATE is a different filter than the caller wrote and
                    // would reach the token silently. The property's guard turns that into a throw.
                    CK_ATTRIBUTE childAttribute = value[i].CkAttribute;
                    UnmanagedMemory.Write(IntPtr.Add(scratch, i * stride), in childAttribute);
                }
                UnmanagedMemory.Read(scratch, flat);
            }
            finally
            {
                UnmanagedMemory.Free(ref scratch);
            }
        }
        _ckAttribute = CreateAttribute(nativeType, flat);
    }

    /// <summary>Creates an attribute holding a list of <c>CK_ULONG</c> values (encoded as a contiguous CK_ULONG[] in unmanaged memory).</summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> or an element of <paramref name="value"/> is wider than this platform's <c>CK_ULONG</c>.</exception>
    public ObjectAttribute(CKA type, IReadOnlyList<ulong> value)
    {
        ArgumentNullException.ThrowIfNull(value);
        NativeCULong nativeType = type.ToCULong();
        int stride = UnmanagedMemory.NativeULongSize;
        byte[] flat = new byte[stride * value.Count];
        for (int i = 0; i < value.Count; i++)
            WriteCULong(flat.AsSpan(i * stride, stride), value[i], nameof(value));
        _ckAttribute = CreateAttribute(nativeType, flat);
    }

    /// <summary>Creates an attribute holding a list of <see cref="CKM"/> values (encoded as a contiguous CK_ULONG[] in unmanaged memory).</summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="type"/> or an element of <paramref name="value"/> is wider than this platform's <c>CK_ULONG</c>.</exception>
    public ObjectAttribute(CKA type, IReadOnlyList<CKM> value)
    {
        ArgumentNullException.ThrowIfNull(value);
        NativeCULong nativeType = type.ToCULong();
        int stride = UnmanagedMemory.NativeULongSize;
        byte[] flat = new byte[stride * value.Count];
        for (int i = 0; i < value.Count; i++)
            WriteCULong(flat.AsSpan(i * stride, stride), (ulong)value[i], nameof(value));
        _ckAttribute = CreateAttribute(nativeType, flat);
    }

    // Writes one CK_ULONG at the platform's width (4 bytes on Windows, 8 on 64-bit Unix), little-endian,
    // after CkULong.From has refused a value that does not fit.
    private static void WriteCULong(Span<byte> destination, ulong value, string paramName)
    {
        _ = CkULong.From(value, paramName);
        if (destination.Length == sizeof(uint))
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(destination, (uint)value);
        else
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(destination, value);
    }

    // --- Read-back -----------------------------------------------------------

    /// <summary>Reads the value as a PKCS#11 <c>CK_BBOOL</c> (single byte; non-zero is <c>true</c>).</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the attribute has been disposed.</exception>
    /// <exception cref="Pkcs11AttributeException">Thrown if the value is unreadable (sensitive or unextractable) or is not exactly one byte.</exception>
    public bool GetValueAsBool()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new Pkcs11AttributeException(Type);
        if ((int)_ckAttribute.valueLen != 1)
            throw new Pkcs11AttributeException(Type);
        byte b = Marshal.ReadByte(_ckAttribute.value);
        return b != 0;
    }

    /// <summary>Reads the value as a platform-width PKCS#11 <c>CK_ULONG</c>.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the attribute has been disposed.</exception>
    /// <exception cref="Pkcs11AttributeException">Thrown if the value is unreadable (sensitive or unextractable) or its length is not that of a platform-width <c>CK_ULONG</c>.</exception>
    public ulong GetValueAsUlong()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new Pkcs11AttributeException(Type);
        int len = (int)_ckAttribute.valueLen;
        if (len != UnmanagedMemory.NativeULongSize)
            throw new Pkcs11AttributeException(Type);
        Span<byte> tmp = stackalloc byte[8];
        UnmanagedMemory.Read(_ckAttribute.value, tmp[..len]);
        return len == 4
            ? System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(tmp[..4])
            : System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(tmp[..8]);
    }

    /// <summary>Reads the value as a UTF-8 string (trailing NUL padding trimmed).</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the attribute has been disposed.</exception>
    /// <exception cref="Pkcs11AttributeException">Thrown if the value is unreadable (sensitive or unextractable).</exception>
    public string GetValueAsString()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new Pkcs11AttributeException(Type);
        int len = (int)_ckAttribute.valueLen;
        if (len == 0) return string.Empty;
        byte[] buf = new byte[len];
        UnmanagedMemory.Read(_ckAttribute.value, buf);
        return Encoding.UTF8.GetString(buf).TrimEnd('\0');
    }

    /// <summary>Returns a copy of the raw value bytes.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the attribute has been disposed.</exception>
    /// <exception cref="Pkcs11AttributeException">Thrown if the value is unreadable (sensitive or unextractable).</exception>
    public byte[] GetValueAsByteArray()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new Pkcs11AttributeException(Type);
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
    /// <exception cref="ObjectDisposedException">Thrown if the attribute has been disposed.</exception>
    /// <exception cref="Pkcs11AttributeException">Thrown if the value is unreadable (sensitive or unextractable).</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="destination"/> is too small.</exception>
    public int CopyValueTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new Pkcs11AttributeException(Type);
        int len = (int)_ckAttribute.valueLen;
        if (destination.Length < len)
            throw new ArgumentException($"Destination too small: needs {len} bytes, got {destination.Length}.", nameof(destination));
        if (len > 0) UnmanagedMemory.Read(_ckAttribute.value, destination[..len]);
        return len;
    }

    /// <summary>Reads the value as a PKCS#11 <c>CK_DATE</c> (UTC); returns <c>null</c> when empty or unparseable.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the attribute has been disposed.</exception>
    /// <exception cref="Pkcs11AttributeException">Thrown if the value is unreadable (sensitive or unextractable) or its length is neither 0 nor 8 bytes.</exception>
    public DateTime? GetValueAsDateTime()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new Pkcs11AttributeException(Type);
        int len = (int)_ckAttribute.valueLen;
        if (len == 0) return null;
        if (len != 8) throw new Pkcs11AttributeException(Type);
        byte[] buf = new byte[8];
        UnmanagedMemory.Read(_ckAttribute.value, buf);
        string s = Encoding.ASCII.GetString(buf);
        if (!DateTime.TryParseExact(s, "yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture,
                                    System.Globalization.DateTimeStyles.None, out DateTime dt))
        {
            return null;
        }
        return DateTime.SpecifyKind(dt, DateTimeKind.Utc);
    }

    /// <summary>Reads the value as a PKCS#11 attribute array (a contiguous <c>CK_ATTRIBUTE[]</c>).</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the attribute has been disposed.</exception>
    /// <exception cref="Pkcs11AttributeException">Thrown if the value is unreadable (sensitive or unextractable) or its length is not a whole multiple of the <c>CK_ATTRIBUTE</c> size.</exception>
    public ObjectAttribute[] GetValueAsAttributeArray()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new Pkcs11AttributeException(Type);
        int total = (int)_ckAttribute.valueLen;
        int stride = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();
        int n = total / stride;
        if (total % stride != 0)
            throw new Pkcs11AttributeException(Type);
        ObjectAttribute[] result = new ObjectAttribute[n];
        for (int i = 0; i < n; i++)
        {
            IntPtr slot = new(_ckAttribute.value.ToInt64() + (long)i * stride);
            CK_ATTRIBUTE attr = UnmanagedMemory.Read<CK_ATTRIBUTE>(slot);
            // Non-owning view: attr.value points at a buffer this attribute's nested children own.
            // Freeing it from here would release memory a live ObjectAttribute still describes.
            result[i] = new ObjectAttribute(attr, ownsValue: false);
        }
        return result;
    }

    /// <summary>Reads the value as a contiguous array of platform-width <c>CK_ULONG</c> values.</summary>
    /// <exception cref="ObjectDisposedException">Thrown if the attribute has been disposed.</exception>
    /// <exception cref="Pkcs11AttributeException">Thrown if the value is unreadable (sensitive or unextractable) or its length is not a whole multiple of the <c>CK_ULONG</c> size.</exception>
    public ulong[] GetValueAsUlongArray()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (CannotBeRead) throw new Pkcs11AttributeException(Type);
        int stride = UnmanagedMemory.NativeULongSize;
        int total = (int)_ckAttribute.valueLen;
        int n = total / stride;
        if (total % stride != 0)
            throw new Pkcs11AttributeException(Type);
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

    /// <summary>Reads the value as an array of <see cref="CKM"/> mechanism types (unvalidated cast from <c>CK_ULONG[]</c>).</summary>
    /// <remarks>
    /// Vendor-defined and not-yet-named mechanisms come back as unnamed <see cref="CKM"/> values.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the attribute has been disposed.</exception>
    /// <exception cref="Pkcs11AttributeException">Thrown if the value is unreadable (sensitive or unextractable) or its length is not a whole multiple of the <c>CK_ULONG</c> size.</exception>
    public CKM[] GetValueAsCkmArray()
    {
        ulong[] raw = GetValueAsUlongArray();
        CKM[] result = new CKM[raw.Length];
        for (int i = 0; i < raw.Length; i++)
            result[i] = (CKM)raw[i];
        return result;
    }

    // --- Diagnostics -------------------------------------------------------

    // CK_BBOOL attributes: a flag is never secret, so its value is safe to print.
    private static readonly HashSet<CKA> FlagAttributes =
    [
        CKA.CKA_TOKEN, CKA.CKA_PRIVATE, CKA.CKA_MODIFIABLE, CKA.CKA_COPYABLE, CKA.CKA_DESTROYABLE,
        CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE, CKA.CKA_ALWAYS_SENSITIVE, CKA.CKA_NEVER_EXTRACTABLE,
        CKA.CKA_LOCAL, CKA.CKA_ENCRYPT, CKA.CKA_DECRYPT, CKA.CKA_WRAP, CKA.CKA_UNWRAP, CKA.CKA_SIGN,
        CKA.CKA_SIGN_RECOVER, CKA.CKA_VERIFY, CKA.CKA_VERIFY_RECOVER, CKA.CKA_DERIVE,
        CKA.CKA_ENCAPSULATE, CKA.CKA_DECAPSULATE, CKA.CKA_WRAP_WITH_TRUSTED, CKA.CKA_TRUSTED,
        CKA.CKA_ALWAYS_AUTHENTICATE,
    ];

    /// <summary>
    /// Returns a description that is safe to log: the attribute's name, and its value only when the
    /// value can never be secret — a flag, an object class, a key or certificate type, a mechanism, or
    /// a size. Every other value is reported by its length alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For example <c>CKA_SENSITIVE = true</c>, <c>CKA_KEY_TYPE = CKK_AES</c>, <c>CKA_VALUE_LEN = 32</c>,
    /// <c>CKA_VALUE (32 bytes)</c>, <c>CKA_LABEL (9 bytes)</c>, <c>CKA_PRIVATE_EXPONENT (unavailable)</c>.
    /// Byte-array and string values — key material, labels, identifiers — are never printed, so a
    /// template or attribute list can be logged or shown in a test failure without leaking a key.
    /// </para>
    /// <para>The format is for diagnostics only and may change; do not parse it.</para>
    /// </remarks>
    /// <returns>A description of the attribute that never contains a byte or string value.</returns>
    public override string ToString()
    {
        if (_disposed) return "ObjectAttribute (disposed)";

        var type = (CKA)(ulong)_ckAttribute.type;
        string name = Pkcs11AttributeException.Describe(type);

        if (_ckAttribute.valueLen == NativeCULong.MaxValue) return $"{name} (unavailable)";

        int length = (int)_ckAttribute.valueLen;
        string? value = DescribeNonSecretValue(type, length);
        return value is null ? $"{name} ({length} bytes)" : $"{name} = {value}";
    }

    // The printable value for an allow-listed attribute of the expected width; null for anything else.
    private string? DescribeNonSecretValue(CKA type, int length)
    {
        if (FlagAttributes.Contains(type))
        {
            if (length != 1) return null;
            return GetValueAsBool() ? "true" : "false";
        }

        if (length != UnmanagedMemory.NativeULongSize) return null;
        return type switch
        {
            CKA.CKA_CLASS => NameOrHex<CKO>(GetValueAsUlong()),
            CKA.CKA_KEY_TYPE => NameOrHex<CKK>(GetValueAsUlong()),
            CKA.CKA_CERTIFICATE_TYPE => NameOrHex<CKC>(GetValueAsUlong()),
            CKA.CKA_KEY_GEN_MECHANISM => NameOrHex<CKM>(GetValueAsUlong()),
            CKA.CKA_VALUE_LEN or CKA.CKA_MODULUS_BITS or CKA.CKA_PRIME_BITS or CKA.CKA_SUBPRIME_BITS
                or CKA.CKA_VALUE_BITS or CKA.CKA_CERTIFICATE_CATEGORY or CKA.CKA_PARAMETER_SET
                => GetValueAsUlong().ToString(System.Globalization.CultureInfo.InvariantCulture),
            _ => null,
        };
    }

    private static string NameOrHex<TEnum>(ulong value) where TEnum : struct, Enum
    {
        var named = (TEnum)Enum.ToObject(typeof(TEnum), value);
        return Enum.IsDefined(named) ? named.ToString() : $"0x{value:X}";
    }

    // --- IDisposable ---------------------------------------------------------

    /// <summary>Frees the unmanaged buffer backing this attribute's value.</summary>
    public void Dispose()
    {
        Release();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Safety net for an attribute that was never disposed. <c>UnmanagedMemory.Free</c> zeroizes
    /// before releasing, so this is what wipes key material — a <c>CKA_VALUE</c> holding imported
    /// key bytes, say — out of unmanaged memory when a caller forgets. Non-owning views suppress
    /// this in their constructor and never reach it.
    /// </summary>
    ~ObjectAttribute() => Release();

    private void Release()
    {
        // Claim atomically: Dispose and the finalizer can race, and UnmanagedMemory.Free throws on a
        // second free — an exception escaping the finalizer thread would tear the process down.
        if (Interlocked.Exchange(ref _releaseClaimed, 1) != 0) return;

        // Publish disposal before freeing, so a concurrent reader is refused rather than handed a
        // pointer that is about to be zeroized.
        _disposed = true;

        if (_ownsValue && _ckAttribute.value != IntPtr.Zero)
            UnmanagedMemory.Free(ref _ckAttribute.value);

        _ckAttribute.valueLen = (NativeCULong)0;
    }

    // --- Private marshalling kernel ------------------------------------------

    private static CK_ATTRIBUTE CreateAttribute(NativeCULong type, ReadOnlySpan<byte> value)
    {
        CK_ATTRIBUTE a = new() { type = type };
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
