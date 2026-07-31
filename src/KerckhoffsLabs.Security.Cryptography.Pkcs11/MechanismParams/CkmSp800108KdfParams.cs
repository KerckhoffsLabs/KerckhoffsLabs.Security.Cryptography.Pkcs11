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
/// A managed descriptor: the whole parameter graph (the PRF data-param array and each segment's
/// value, the feedback IV, and the additional-derived-key array with its per-key templates and
/// handle slots) is rebuilt into the call's own scope on each use, and owns nothing beyond it. When
/// additional derived keys were requested, read <see cref="AdditionalDerivedKeys"/> after the
/// <c>C_DeriveKey</c> call — the session copies the handles out of the scope before releasing it.
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

    // Keeps the caller's derived-key attribute objects rooted so their unmanaged value buffers
    // (referenced by the marshalled CK_ATTRIBUTE pointers) are not finalized before the derive call.
    private readonly List<IReadOnlyList<ObjectAttribute>> _retainedTemplates;

    // Managed description of the parameter graph, kept so it can be rebuilt inside a call scope.
    private readonly CKM _prfType;
    private readonly Sp800108Segment[] _segments;
    private readonly byte[] _iv;
    // Handles copied out of the scope-owned CK_DERIVED_KEY array by AbsorbOutput, before the scope
    // that holds the slots is released.
    private readonly List<ulong> _derivedHandles = [];

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
        _prfType = builder.PrfType;
        _segments = [.. builder.Segments];
        _iv = builder.Iv.IsEmpty ? [] : builder.Iv.ToArray();
    }

    /// <summary>
    /// Raw <c>CK_OBJECT_HANDLE</c> values of the additional sibling keys derived in the same call, in
    /// the order added via <see cref="Sp800108KdfBuilder.AddDerivedKey"/>. Read after the
    /// <c>C_DeriveKey</c> call. Empty when none were requested, and also before the call: the handles
    /// live in the call scope's memory until the derive absorbs them out of it. A slot the token left
    /// unwritten reads as <c>CK_INVALID_HANDLE</c> (0).
    /// </summary>
    /// <remarks>
    /// A snapshot, not a view: the returned list does not change when a later call absorbs again.
    /// </remarks>
    public IReadOnlyList<ulong> AdditionalDerivedKeys
    {
        get
        {
            ulong[] snapshot = [.. _derivedHandles];
            return snapshot;
        }
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {

        // Inner blocks first: every CK_PRF_DATA_PARAM stores the address of its format struct or
        // byte array, and every CK_DERIVED_KEY stores the addresses of its attribute template and
        // its handle slot. Those blocks have to exist before the array that records their addresses
        // is written, so the arrays are built last.
        var prfEntries = new CK_PRF_DATA_PARAM[_segments.Length];
        for (int i = 0; i < _segments.Length; i++)
            prfEntries[i] = BuildPrfEntry(_segments[i], scope);
        IntPtr dataParams = scope.WriteStructArray<CK_PRF_DATA_PARAM>(prfEntries);

        IntPtr derivedKeys = IntPtr.Zero;
        if (_retainedTemplates.Count > 0)
        {
            var entries = new CK_DERIVED_KEY[_retainedTemplates.Count];
            for (int j = 0; j < _retainedTemplates.Count; j++)
                entries[j] = BuildDerivedKey(_retainedTemplates[j], scope);
            derivedKeys = scope.WriteStructArray<CK_DERIVED_KEY>(entries);
        }

        var dataParamCount = (NativeCULong)(ulong)_segments.Length;
        var derivedKeyCount = (NativeCULong)(ulong)_retainedTemplates.Count;

        // Feedback mode has its own top-level struct; counter and double-pipeline share one.
        if (_feedback)
        {
            return new CK_SP800_108_FEEDBACK_KDF_PARAMS
            {
                PrfType = _prfType.ToCULong(),
                NumberOfDataParams = dataParamCount,
                DataParams = dataParams,
                IVLen = (NativeCULong)_iv.Length,
                IV = scope.Write(_iv),
                AdditionalDerivedKeys = derivedKeyCount,
                AdditionalDerivedKeysPtr = derivedKeys,
            };
        }

        return new CK_SP800_108_KDF_PARAMS
        {
            PrfType = _prfType.ToCULong(),
            NumberOfDataParams = dataParamCount,
            DataParams = dataParams,
            AdditionalDerivedKeys = derivedKeyCount,
            AdditionalDerivedKeysPtr = derivedKeys,
        };
    }

    /// <inheritdoc/>
    /// <inheritdoc/>
    internal override bool AbsorbsTokenOutput => true;

    internal override void AbsorbOutput(object marshalled)
    {

        if (_retainedTemplates.Count == 0) return;

        IntPtr array = ExtractAdditionalDerivedKeysPointer(marshalled);
        if (array == IntPtr.Zero) return;

        int size = UnmanagedMemory.SizeOf<CK_DERIVED_KEY>();
        _derivedHandles.Clear();
        for (int j = 0; j < _retainedTemplates.Count; j++)
        {
            var entry = UnmanagedMemory.Read<CK_DERIVED_KEY>(IntPtr.Add(array, j * size));
            // Key is a CK_OBJECT_HANDLE_PTR — the handle the token wrote lives in the slot it
            // addresses, not in the field itself.
            _derivedHandles.Add(entry.Key == IntPtr.Zero ? 0UL : ReadHandle(entry.Key));
        }
    }

    /// <summary>
    /// Reads the <c>CK_DERIVED_KEY</c> array pointer out of whichever top-level struct the mode used.
    /// Counter and double-pipeline mode both marshal <see cref="CK_SP800_108_KDF_PARAMS"/>.
    /// </summary>
    private static IntPtr ExtractAdditionalDerivedKeysPointer(object marshalled) => marshalled switch
    {
        CK_SP800_108_KDF_PARAMS p => p.AdditionalDerivedKeysPtr,
        CK_SP800_108_FEEDBACK_KDF_PARAMS f => f.AdditionalDerivedKeysPtr,
        _ => IntPtr.Zero,
    };

    private static CK_PRF_DATA_PARAM BuildPrfEntry(Sp800108Segment seg, MechanismParameterScope scope)
    {
        ulong type;
        IntPtr value;
        int valueLen;

        switch (seg.Kind)
        {
            case Sp800108SegmentKind.IterationCounter:
            case Sp800108SegmentKind.OptionalCounter:
                {
                    valueLen = UnmanagedMemory.SizeOf<CK_SP800_108_COUNTER_FORMAT>();
                    value = scope.WriteStruct(new CK_SP800_108_COUNTER_FORMAT
                    {
                        LittleEndian = seg.LittleEndian,
                        WidthInBits = (NativeCULong)seg.WidthInBits,
                    });
                    type = seg.Kind == Sp800108SegmentKind.IterationCounter
                        ? CK_SP800_108_ITERATION_VARIABLE
                        : CK_SP800_108_OPTIONAL_COUNTER;
                    break;
                }

            case Sp800108SegmentKind.DkmLength:
                {
                    valueLen = UnmanagedMemory.SizeOf<CK_SP800_108_DKM_LENGTH_FORMAT>();
                    value = scope.WriteStruct(new CK_SP800_108_DKM_LENGTH_FORMAT
                    {
                        DkmLengthMethod = (NativeCULong)(ulong)seg.DkmMethod,
                        LittleEndian = seg.LittleEndian,
                        WidthInBits = (NativeCULong)seg.WidthInBits,
                    });
                    type = CK_SP800_108_DKM_LENGTH;
                    break;
                }

            case Sp800108SegmentKind.KeyHandle:
                {
                    valueLen = UnmanagedMemory.NativeULongSize;
                    value = scope.Allocate(valueLen);
                    WriteHandle(value, seg.KeyHandle);
                    type = CK_SP800_108_KEY_HANDLE;
                    break;
                }

            case Sp800108SegmentKind.ByteArray:
            default:
                {
                    byte[] bytes = seg.Bytes ?? [];
                    valueLen = bytes.Length;
                    value = scope.Write(bytes);
                    type = CK_SP800_108_BYTE_ARRAY;
                    break;
                }
        }

        return new CK_PRF_DATA_PARAM
        {
            Type = (NativeCULong)type,
            Value = value,
            ValueLen = (NativeCULong)(ulong)valueLen,
        };
    }

    private static CK_DERIVED_KEY BuildDerivedKey(IReadOnlyList<ObjectAttribute> template, MechanismParameterScope scope)
    {
        IntPtr templatePtr = IntPtr.Zero;
        if (template.Count > 0)
        {
            var attributes = new CK_ATTRIBUTE[template.Count];
            for (int k = 0; k < template.Count; k++)
                attributes[k] = template[k].CkAttribute;
            templatePtr = scope.WriteStructArray<CK_ATTRIBUTE>(attributes);
        }

        return new CK_DERIVED_KEY
        {
            Template = templatePtr,
            AttributeCount = (NativeCULong)(ulong)template.Count,
            Key = scope.Allocate(UnmanagedMemory.NativeULongSize), // zero-filled = CK_INVALID_HANDLE
        };
    }

    // ---- handle marshalling at the platform's CK_ULONG width ----

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
}
