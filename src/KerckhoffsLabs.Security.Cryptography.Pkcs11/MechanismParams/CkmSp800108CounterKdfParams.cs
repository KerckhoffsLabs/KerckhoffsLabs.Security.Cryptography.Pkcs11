using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_SP800_108_KDF_PARAMS"/> specialized to NIST SP800-108
/// <b>counter mode</b> (<c>CKM_SP800_108_COUNTER_KDF</c>, PKCS#11 v3.0) with the same fixed-input
/// layout as the BCL <see cref="System.Security.Cryptography.SP800108HmacCounterKdf"/>:
/// <code>K(i) = PRF(KI, [i]₃₂ ‖ Label ‖ 0x00 ‖ Context ‖ [L]₃₂)</code>
/// where the counter <c>[i]</c> and the derived-key bit length <c>[L]</c> are 32-bit big-endian, and
/// <c>L</c> is the sum of the derived keys' lengths (i.e. the requested output length, taken from the
/// derived key's <c>CKA_VALUE_LEN</c>).
/// </summary>
/// <remarks>
/// Owns every unmanaged buffer it allocates (the <see cref="CK_PRF_DATA_PARAM"/> array, the counter /
/// DKM-length format sub-structs, and the label / separator / context byte buffers). Per the
/// <see cref="Mechanism"/> contract, dispose this instance <b>after</b> the mechanism that references
/// it — the <c>DataParams</c> pointer must stay valid for the duration of the <c>C_DeriveKey</c> call.
/// </remarks>
public sealed class CkmSp800108CounterKdfParams : MechanismParameters
{
    // PKCS#11 v3.0 data-param type tags and DKM-length method (OASIS pkcs11t.h).
    private const ulong CK_SP800_108_ITERATION_VARIABLE = 1UL;
    private const ulong CK_SP800_108_DKM_LENGTH = 3UL;
    private const ulong CK_SP800_108_BYTE_ARRAY = 4UL;
    private const ulong CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS = 1UL;
    private const ulong CounterAndLengthWidthBits = 32UL;
    private const int DataParamCount = 5;

    private CK_SP800_108_KDF_PARAMS _lowLevelParams;
    private IntPtr _dataParams;       // CK_PRF_DATA_PARAM[DataParamCount]
    private IntPtr _counterFormat;    // CK_SP800_108_COUNTER_FORMAT
    private IntPtr _dkmLengthFormat;  // CK_SP800_108_DKM_LENGTH_FORMAT
    private IntPtr _label;
    private IntPtr _separator;        // single 0x00 byte
    private IntPtr _context;
    private bool _disposed;

    /// <summary>
    /// Builds the counter-mode data sequence for the given PRF, label and context.
    /// </summary>
    /// <param name="prfType">PRF mechanism — a <c>CKM_*_HMAC</c> variant or <c>CKM_AES_CMAC</c>.</param>
    /// <param name="label">Label bytes (the SP800-108 <c>Label</c>); may be empty.</param>
    /// <param name="context">Context bytes (the SP800-108 <c>Context</c>); may be empty.</param>
    public CkmSp800108CounterKdfParams(CKM prfType, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context)
    {
        // Counter format: 32-bit big-endian iteration variable (matches the BCL / NIST default).
        int counterSize = UnmanagedMemory.SizeOf(typeof(CK_SP800_108_COUNTER_FORMAT));
        _counterFormat = UnmanagedMemory.Allocate(counterSize);
        UnmanagedMemory.Write(_counterFormat, (object)new CK_SP800_108_COUNTER_FORMAT
        {
            LittleEndian = false,
            WidthInBits = (NativeCULong)CounterAndLengthWidthBits,
        });

        // DKM-length format: 32-bit big-endian [L], where L is the sum of derived key lengths in bits.
        int dkmSize = UnmanagedMemory.SizeOf(typeof(CK_SP800_108_DKM_LENGTH_FORMAT));
        _dkmLengthFormat = UnmanagedMemory.Allocate(dkmSize);
        UnmanagedMemory.Write(_dkmLengthFormat, (object)new CK_SP800_108_DKM_LENGTH_FORMAT
        {
            DkmLengthMethod = (NativeCULong)CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS,
            LittleEndian = false,
            WidthInBits = (NativeCULong)CounterAndLengthWidthBits,
        });

        _label = AllocateBytes(label);
        _separator = UnmanagedMemory.Allocate(1);
        UnmanagedMemory.Write(_separator, (ReadOnlySpan<byte>)stackalloc byte[] { 0x00 });
        _context = AllocateBytes(context);

        int elemSize = UnmanagedMemory.SizeOf(typeof(CK_PRF_DATA_PARAM));
        _dataParams = UnmanagedMemory.Allocate(elemSize * DataParamCount);
        WriteDataParam(0, elemSize, CK_SP800_108_ITERATION_VARIABLE, _counterFormat, counterSize);
        WriteDataParam(1, elemSize, CK_SP800_108_BYTE_ARRAY, _label, label.Length);
        WriteDataParam(2, elemSize, CK_SP800_108_BYTE_ARRAY, _separator, 1);
        WriteDataParam(3, elemSize, CK_SP800_108_BYTE_ARRAY, _context, context.Length);
        WriteDataParam(4, elemSize, CK_SP800_108_DKM_LENGTH, _dkmLengthFormat, dkmSize);

        _lowLevelParams = new()
        {
            PrfType = prfType.ToCULong(),
            NumberOfDataParams = (NativeCULong)(ulong)DataParamCount,
            DataParams = _dataParams,
            AdditionalDerivedKeys = (NativeCULong)0,
            AdditionalDerivedKeysPtr = IntPtr.Zero,
        };
    }

    private static IntPtr AllocateBytes(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return IntPtr.Zero; // an empty BYTE_ARRAY contributes nothing; NULL pValue with ValueLen 0.
        IntPtr p = UnmanagedMemory.Allocate(data.Length);
        UnmanagedMemory.Write(p, data);
        return p;
    }

    private void WriteDataParam(int index, int elemSize, ulong type, IntPtr value, long valueLen) =>
        UnmanagedMemory.Write(_dataParams + (index * elemSize), (object)new CK_PRF_DATA_PARAM
        {
            Type = (NativeCULong)type,
            Value = value,
            ValueLen = (NativeCULong)(ulong)valueLen,
        });

    /// <inheritdoc/>
    internal override object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    public override void Dispose()
    {
        if (_disposed) return;
        UnmanagedMemory.Free(ref _dataParams);
        UnmanagedMemory.Free(ref _counterFormat);
        UnmanagedMemory.Free(ref _dkmLengthFormat);
        UnmanagedMemory.Free(ref _label);
        UnmanagedMemory.Free(ref _separator);
        UnmanagedMemory.Free(ref _context);
        _lowLevelParams.DataParams = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmSp800108CounterKdfParams() => Dispose();
}
