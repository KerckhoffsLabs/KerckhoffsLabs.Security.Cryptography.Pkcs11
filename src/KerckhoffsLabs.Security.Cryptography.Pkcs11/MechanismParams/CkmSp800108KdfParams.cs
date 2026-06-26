using System.Buffers.Binary;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// Parameters for the PKCS#11 v3.0 SP800-108 key-derivation functions — counter
/// (<c>CKM_SP800_108_COUNTER_KDF</c>), feedback (<c>CKM_SP800_108_FEEDBACK_KDF</c>), and
/// double-pipeline (<c>CKM_SP800_108_DOUBLE_PIPELINE_KDF</c>). Build one with the fluent entry
/// points (<see cref="Counter"/> / <see cref="Feedback"/> / <see cref="DoublePipeline"/>) or the
/// <see cref="CounterModeHmac"/> preset, then pass it to a <see cref="Mechanism"/> with the matching
/// mechanism type.
/// </summary>
/// <remarks>
/// Owns every unmanaged buffer it allocates (the PRF data-param array and each segment's value,
/// the feedback IV, and the additional-derived-key array with its per-key templates and handle
/// slots). Per the <see cref="Mechanism"/> contract, dispose this <b>after</b> the mechanism that
/// references it. When additional derived keys were requested, read
/// <see cref="AdditionalDerivedKeys"/> after the <c>C_DeriveKey</c> call but before disposing.
/// </remarks>
public sealed class CkmSp800108KdfParams : MechanismParameters
{
    // CK_PRF_DATA_TYPE tags (OASIS pkcs11t.h).
    private const ulong CK_SP800_108_ITERATION_VARIABLE = 1UL;
    private const ulong CK_SP800_108_OPTIONAL_COUNTER = 2UL;
    private const ulong CK_SP800_108_DKM_LENGTH = 3UL;
    private const ulong CK_SP800_108_BYTE_ARRAY = 4UL;
    private const ulong CK_SP800_108_KEY_HANDLE = 5UL;

    private readonly bool _feedback;
    private CK_SP800_108_KDF_PARAMS _counterParams;
    private CK_SP800_108_FEEDBACK_KDF_PARAMS _feedbackParams;

    private readonly List<IntPtr> _owned = [];
    // Keeps the caller's derived-key attribute objects rooted so their unmanaged value buffers
    // (referenced by the marshalled CK_ATTRIBUTE pointers) are not finalized before the derive call.
    private readonly List<IReadOnlyList<ObjectAttribute>> _retainedTemplates;
    private readonly IntPtr[] _derivedKeyHandleSlots;
    private bool _disposed;

    /// <summary>Begins a counter-mode (<c>CKM_SP800_108_COUNTER_KDF</c>) parameter build.</summary>
    public static Sp800108KdfBuilder Counter(CKM prfType) => new(prfType, Sp800108KdfMode.Counter);

    /// <summary>Begins a feedback-mode (<c>CKM_SP800_108_FEEDBACK_KDF</c>) parameter build.</summary>
    public static Sp800108KdfBuilder Feedback(CKM prfType) => new(prfType, Sp800108KdfMode.Feedback);

    /// <summary>Begins a double-pipeline-mode (<c>CKM_SP800_108_DOUBLE_PIPELINE_KDF</c>) parameter build.</summary>
    public static Sp800108KdfBuilder DoublePipeline(CKM prfType) => new(prfType, Sp800108KdfMode.DoublePipeline);

    /// <summary>
    /// Convenience preset for counter mode with the fixed NIST/BCL layout
    /// <c>[i]32 || Label || 0x00 || Context || [L]32</c> (big-endian, L = sum of derived key lengths) —
    /// the same construction as <see cref="System.Security.Cryptography.SP800108HmacCounterKdf"/>.
    /// </summary>
    public static CkmSp800108KdfParams CounterModeHmac(CKM prfType, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context) =>
        Counter(prfType)
            .IterationCounter(widthInBits: 32, littleEndian: false)
            .ByteArray(label)
            .ByteArray([0x00])
            .ByteArray(context)
            .DkmLength(Sp800108DkmLengthMethod.SumOfKeys, widthInBits: 32, littleEndian: false)
            .Build();

    internal CkmSp800108KdfParams(Sp800108KdfBuilder builder)
    {
        _feedback = builder.Mode == Sp800108KdfMode.Feedback;
        _retainedTemplates = [.. builder.DerivedKeys];

        IntPtr dataParams = MarshalDataParams(builder.Segments, out NativeCULong dataParamCount);
        IntPtr derivedKeys = MarshalDerivedKeys(builder.DerivedKeys, out NativeCULong derivedKeyCount, out _derivedKeyHandleSlots);

        if (_feedback)
        {
            IntPtr iv = AllocateBytes(builder.Iv);
            _feedbackParams = new CK_SP800_108_FEEDBACK_KDF_PARAMS
            {
                PrfType = builder.PrfType.ToCULong(),
                NumberOfDataParams = dataParamCount,
                DataParams = dataParams,
                IVLen = (NativeCULong)builder.Iv.Length,
                IV = iv,
                AdditionalDerivedKeys = derivedKeyCount,
                AdditionalDerivedKeysPtr = derivedKeys,
            };
        }
        else
        {
            _counterParams = new CK_SP800_108_KDF_PARAMS
            {
                PrfType = builder.PrfType.ToCULong(),
                NumberOfDataParams = dataParamCount,
                DataParams = dataParams,
                AdditionalDerivedKeys = derivedKeyCount,
                AdditionalDerivedKeysPtr = derivedKeys,
            };
        }
    }

    /// <summary>
    /// Raw <c>CK_OBJECT_HANDLE</c> values of the additional sibling keys derived in the same call, in
    /// the order added via <see cref="Sp800108KdfBuilder.AddDerivedKey"/>. Read after the
    /// <c>C_DeriveKey</c> call; values are <c>CK_INVALID_HANDLE</c> (0) until the token populates them.
    /// Empty when none were requested.
    /// </summary>
    public IReadOnlyList<ulong> AdditionalDerivedKeys
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ulong[] handles = new ulong[_derivedKeyHandleSlots.Length];
            for (int i = 0; i < _derivedKeyHandleSlots.Length; i++)
                handles[i] = ReadHandle(_derivedKeyHandleSlots[i]);
            return handles;
        }
    }

    /// <inheritdoc/>
    internal override object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _feedback ? _feedbackParams : _counterParams;
    }

    // ---- marshalling helpers ----

    private IntPtr Track(int size)
    {
        IntPtr p = UnmanagedMemory.Allocate(size);
        _owned.Add(p);
        return p;
    }

    private IntPtr AllocateBytes(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return IntPtr.Zero;
        IntPtr p = Track(data.Length);
        UnmanagedMemory.Write(p, data);
        return p;
    }

    private IntPtr MarshalDataParams(IReadOnlyList<Sp800108Segment> segments, out NativeCULong count)
    {
        int prfSize = UnmanagedMemory.SizeOf<CK_PRF_DATA_PARAM>();
        IntPtr array = Track(prfSize * segments.Count);

        for (int i = 0; i < segments.Count; i++)
        {
            (ulong type, IntPtr value, int valueLen) = MarshalSegment(segments[i]);
            var entry = new CK_PRF_DATA_PARAM
            {
                Type = (NativeCULong)type,
                Value = value,
                ValueLen = (NativeCULong)(ulong)valueLen,
            };
            UnmanagedMemory.Write(array + (i * prfSize), in entry);
        }

        count = (NativeCULong)(ulong)segments.Count;
        return array;
    }

    private (ulong Type, IntPtr Value, int ValueLen) MarshalSegment(Sp800108Segment seg)
    {
        switch (seg.Kind)
        {
            case Sp800108SegmentKind.IterationCounter:
            case Sp800108SegmentKind.OptionalCounter:
                {
                    int size = UnmanagedMemory.SizeOf<CK_SP800_108_COUNTER_FORMAT>();
                    IntPtr p = Track(size);
                    UnmanagedMemory.Write(p, (object)new CK_SP800_108_COUNTER_FORMAT
                    {
                        LittleEndian = seg.LittleEndian,
                        WidthInBits = (NativeCULong)seg.WidthInBits,
                    });
                    ulong tag = seg.Kind == Sp800108SegmentKind.IterationCounter
                        ? CK_SP800_108_ITERATION_VARIABLE
                        : CK_SP800_108_OPTIONAL_COUNTER;
                    return (tag, p, size);
                }

            case Sp800108SegmentKind.DkmLength:
                {
                    int size = UnmanagedMemory.SizeOf<CK_SP800_108_DKM_LENGTH_FORMAT>();
                    IntPtr p = Track(size);
                    UnmanagedMemory.Write(p, (object)new CK_SP800_108_DKM_LENGTH_FORMAT
                    {
                        DkmLengthMethod = (NativeCULong)(ulong)seg.DkmMethod,
                        LittleEndian = seg.LittleEndian,
                        WidthInBits = (NativeCULong)seg.WidthInBits,
                    });
                    return (CK_SP800_108_DKM_LENGTH, p, size);
                }

            case Sp800108SegmentKind.KeyHandle:
                {
                    IntPtr p = Track(UnmanagedMemory.NativeULongSize);
                    WriteHandle(p, seg.KeyHandle);
                    return (CK_SP800_108_KEY_HANDLE, p, UnmanagedMemory.NativeULongSize);
                }

            case Sp800108SegmentKind.ByteArray:
            default:
                {
                    byte[] bytes = seg.Bytes ?? [];
                    return (CK_SP800_108_BYTE_ARRAY, AllocateBytes(bytes), bytes.Length);
                }
        }
    }

    private IntPtr MarshalDerivedKeys(IReadOnlyList<IReadOnlyList<ObjectAttribute>> derivedKeys, out NativeCULong count, out IntPtr[] handleSlots)
    {
        count = (NativeCULong)(ulong)derivedKeys.Count;
        if (derivedKeys.Count == 0)
        {
            handleSlots = [];
            return IntPtr.Zero;
        }

        int dkSize = UnmanagedMemory.SizeOf<CK_DERIVED_KEY>();
        int attrSize = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();
        IntPtr array = Track(dkSize * derivedKeys.Count);
        handleSlots = new IntPtr[derivedKeys.Count];

        for (int j = 0; j < derivedKeys.Count; j++)
        {
            IReadOnlyList<ObjectAttribute> template = derivedKeys[j];
            IntPtr templatePtr = template.Count > 0 ? Track(attrSize * template.Count) : IntPtr.Zero;
            for (int k = 0; k < template.Count; k++)
            {
                CK_ATTRIBUTE attr = template[k].CkAttribute;
                UnmanagedMemory.Write(templatePtr + (k * attrSize), in attr);
            }

            IntPtr keySlot = Track(UnmanagedMemory.NativeULongSize); // zero-filled = CK_INVALID_HANDLE
            handleSlots[j] = keySlot;

            var derived = new CK_DERIVED_KEY
            {
                Template = templatePtr,
                AttributeCount = (NativeCULong)(ulong)template.Count,
                Key = keySlot,
            };
            UnmanagedMemory.Write(array + (j * dkSize), in derived);
        }

        return array;
    }

    private static void WriteHandle(IntPtr destination, ulong handle)
    {
        Span<byte> tmp = stackalloc byte[8];
        if (UnmanagedMemory.NativeULongSize == 4)
            BinaryPrimitives.WriteUInt32LittleEndian(tmp, checked((uint)handle));
        else
            BinaryPrimitives.WriteUInt64LittleEndian(tmp, handle);
        UnmanagedMemory.Write(destination, tmp[..UnmanagedMemory.NativeULongSize]);
    }

    private static ulong ReadHandle(IntPtr source)
    {
        byte[] buffer = UnmanagedMemory.Read(source, UnmanagedMemory.NativeULongSize);
        return UnmanagedMemory.NativeULongSize == 4
            ? BinaryPrimitives.ReadUInt32LittleEndian(buffer)
            : BinaryPrimitives.ReadUInt64LittleEndian(buffer);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;

        for (int i = 0; i < _owned.Count; i++)
        {
            IntPtr p = _owned[i];
            UnmanagedMemory.Free(ref p);
        }
        _owned.Clear();

        _counterParams.DataParams = IntPtr.Zero;
        _counterParams.AdditionalDerivedKeysPtr = IntPtr.Zero;
        _feedbackParams.DataParams = IntPtr.Zero;
        _feedbackParams.IV = IntPtr.Zero;
        _feedbackParams.AdditionalDerivedKeysPtr = IntPtr.Zero;
        _disposed = true;
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmSp800108KdfParams() => Dispose(false);
}
