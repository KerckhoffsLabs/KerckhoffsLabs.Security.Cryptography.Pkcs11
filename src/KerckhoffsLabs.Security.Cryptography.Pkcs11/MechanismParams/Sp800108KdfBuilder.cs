using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>One of the SP800-108 key-derivation modes.</summary>
internal enum Sp800108KdfMode
{
    /// <summary>Counter mode — <c>CKM_SP800_108_COUNTER_KDF</c>.</summary>
    Counter,

    /// <summary>Feedback mode (with chaining IV) — <c>CKM_SP800_108_FEEDBACK_KDF</c>.</summary>
    Feedback,

    /// <summary>Double-pipeline mode — <c>CKM_SP800_108_DOUBLE_PIPELINE_KDF</c>.</summary>
    DoublePipeline,
}

/// <summary>Kind of one SP800-108 PRF data segment (maps to a <c>CK_PRF_DATA_TYPE</c> tag).</summary>
internal enum Sp800108SegmentKind
{
    IterationCounter,   // CK_SP800_108_ITERATION_VARIABLE
    OptionalCounter,    // CK_SP800_108_OPTIONAL_COUNTER
    ByteArray,          // CK_SP800_108_BYTE_ARRAY
    DkmLength,          // CK_SP800_108_DKM_LENGTH
    KeyHandle,          // CK_SP800_108_KEY_HANDLE
}

/// <summary>One described (not-yet-marshalled) SP800-108 PRF data segment.</summary>
internal readonly struct Sp800108Segment
{
    public Sp800108SegmentKind Kind { get; init; }
    public byte[]? Bytes { get; init; }
    public uint WidthInBits { get; init; }
    public bool LittleEndian { get; init; }
    public Sp800108DkmLengthMethod DkmMethod { get; init; }
    public ulong KeyHandle { get; init; }
}

/// <summary>
/// Fluent builder for the PKCS#11 v3.0 SP800-108 KDFs. Assembles the PRF data sequence
/// (iteration/optional counters, byte arrays, DKM-length encoding, and key-handle splices),
/// the feedback IV, and any additional sibling keys to derive in the same call, then produces a
/// <see cref="CkmSp800108KdfParams"/> that owns all the unmanaged buffers.
/// </summary>
/// <remarks>
/// Obtain an instance via <see cref="CkmSp800108KdfParams.Counter"/>,
/// <see cref="CkmSp800108KdfParams.Feedback"/>, or <see cref="CkmSp800108KdfParams.DoublePipeline"/>.
/// </remarks>
public sealed class Sp800108KdfBuilder
{
    private readonly CKM _prfType;
    private readonly Sp800108KdfMode _mode;
    private readonly List<Sp800108Segment> _segments = [];
    private readonly List<IReadOnlyList<ObjectAttribute>> _derivedKeys = [];
    private byte[]? _iv;

    internal Sp800108KdfBuilder(CKM prfType, Sp800108KdfMode mode)
    {
        _prfType = prfType;
        _mode = mode;
    }

    internal CKM PrfType => _prfType;
    internal Sp800108KdfMode Mode => _mode;
    internal IReadOnlyList<Sp800108Segment> Segments => _segments;
    internal IReadOnlyList<IReadOnlyList<ObjectAttribute>> DerivedKeys => _derivedKeys;
    internal ReadOnlySpan<byte> Iv => _iv;

    /// <summary>Appends the mandatory iteration counter (<c>CK_SP800_108_ITERATION_VARIABLE</c>).</summary>
    /// <param name="widthInBits">Counter width in bits (NIST default 32).</param>
    /// <param name="littleEndian"><c>false</c> for big-endian (the NIST/BCL default).</param>
    public Sp800108KdfBuilder IterationCounter(uint widthInBits = 32, bool littleEndian = false)
    {
        _segments.Add(new Sp800108Segment { Kind = Sp800108SegmentKind.IterationCounter, WidthInBits = widthInBits, LittleEndian = littleEndian });
        return this;
    }

    /// <summary>Appends an additional counter segment (<c>CK_SP800_108_OPTIONAL_COUNTER</c>), used by feedback / double-pipeline layouts.</summary>
    public Sp800108KdfBuilder OptionalCounter(uint widthInBits = 32, bool littleEndian = false)
    {
        _segments.Add(new Sp800108Segment { Kind = Sp800108SegmentKind.OptionalCounter, WidthInBits = widthInBits, LittleEndian = littleEndian });
        return this;
    }

    /// <summary>Appends a literal byte segment (<c>CK_SP800_108_BYTE_ARRAY</c>) — e.g. Label, a 0x00 separator, or Context.</summary>
    public Sp800108KdfBuilder ByteArray(ReadOnlySpan<byte> data)
    {
        _segments.Add(new Sp800108Segment { Kind = Sp800108SegmentKind.ByteArray, Bytes = data.ToArray() });
        return this;
    }

    /// <summary>Appends the derived-keying-material length encoding (<c>CK_SP800_108_DKM_LENGTH</c>).</summary>
    public Sp800108KdfBuilder DkmLength(Sp800108DkmLengthMethod method, uint widthInBits = 32, bool littleEndian = false)
    {
        _segments.Add(new Sp800108Segment { Kind = Sp800108SegmentKind.DkmLength, DkmMethod = method, WidthInBits = widthInBits, LittleEndian = littleEndian });
        return this;
    }

    /// <summary>
    /// Splices another on-token key's value into the PRF input by its object handle
    /// (<c>CK_SP800_108_KEY_HANDLE</c>). Handles are raw <c>CK_OBJECT_HANDLE</c> values, matching the
    /// other handle-valued mechanism parameters in this namespace.
    /// </summary>
    public Sp800108KdfBuilder KeyHandle(ulong key)
    {
        _segments.Add(new Sp800108Segment { Kind = Sp800108SegmentKind.KeyHandle, KeyHandle = key });
        return this;
    }

    /// <summary>Sets the feedback-chaining IV. Valid only in feedback mode.</summary>
    /// <exception cref="InvalidOperationException">Thrown if the builder is not in feedback mode.</exception>
    public Sp800108KdfBuilder WithIV(ReadOnlySpan<byte> iv)
    {
        if (_mode != Sp800108KdfMode.Feedback)
            throw new InvalidOperationException("WithIV is only valid for the feedback KDF (CkmSp800108KdfParams.Feedback).");
        _iv = iv.ToArray();
        return this;
    }

    /// <summary>
    /// Requests an additional sibling key to be derived in the same <c>C_DeriveKey</c> call
    /// (<c>CK_DERIVED_KEY</c> / <c>ulAdditionalDerivedKeys</c>). The resulting handles are read back
    /// from <see cref="CkmSp800108KdfParams.AdditionalDerivedKeys"/> after the derive completes.
    /// The caller retains ownership of the <paramref name="template"/> attributes and must keep them
    /// alive (undisposed) until after the derive call.
    /// </summary>
    public Sp800108KdfBuilder AddDerivedKey(IReadOnlyList<ObjectAttribute> template)
    {
        ArgumentNullException.ThrowIfNull(template);
        _derivedKeys.Add(template);
        return this;
    }

    /// <summary>Marshals the configured parameters into a <see cref="CkmSp800108KdfParams"/> that owns the unmanaged buffers.</summary>
    /// <exception cref="InvalidOperationException">Thrown if no data segment was added.</exception>
    public CkmSp800108KdfParams Build()
    {
        if (_segments.Count == 0)
            throw new InvalidOperationException("An SP800-108 KDF needs at least one data segment (start with IterationCounter()).");
        return new CkmSp800108KdfParams(this);
    }
}
