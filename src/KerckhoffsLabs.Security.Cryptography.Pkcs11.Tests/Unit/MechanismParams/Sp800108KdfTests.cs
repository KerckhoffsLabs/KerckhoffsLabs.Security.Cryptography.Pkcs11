using System.Buffers.Binary;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// Hermetic marshalling coverage for the general SP800-108 KDF surface: all three modes, every PRF
/// data-segment type (iteration/optional counters, byte arrays, DKM-length, key-handle), the format
/// sub-structs (endianness/width/method), builder validation, and multi-key derivation with handle
/// read-back. Neither SoftHSM nor opencryptoki implements these mechanisms, so this is the primary
/// correctness check on the unmanaged construction.
/// </summary>
public sealed class Sp800108KdfTests
{
    private const ulong IterationVariable = 1, OptionalCounter = 2, DkmLengthTag = 3, ByteArrayTag = 4, KeyHandleTag = 5;

    private static int Elem => UnmanagedMemory.SizeOf(typeof(CK_PRF_DATA_PARAM));
    private static CK_PRF_DATA_PARAM Param(IntPtr array, int i) => UnmanagedMemory.Read<CK_PRF_DATA_PARAM>(array + (i * Elem));

    private static ulong ReadHandle(IntPtr slot)
    {
        byte[] b = UnmanagedMemory.Read(slot, UnmanagedMemory.NativeULongSize);
        return UnmanagedMemory.NativeULongSize == 4 ? BinaryPrimitives.ReadUInt32LittleEndian(b) : BinaryPrimitives.ReadUInt64LittleEndian(b);
    }

    private static void WriteHandle(IntPtr slot, ulong handle)
    {
        Span<byte> t = stackalloc byte[8];
        if (UnmanagedMemory.NativeULongSize == 4) BinaryPrimitives.WriteUInt32LittleEndian(t, (uint)handle);
        else BinaryPrimitives.WriteUInt64LittleEndian(t, handle);
        UnmanagedMemory.Write(slot, t[..UnmanagedMemory.NativeULongSize]);
    }

    [Fact]
    public void Counter_AllSegmentTypes_MarshalWithFormatsAndKeyHandle()
    {
        const ulong spliceKey = 0xABCD;
        byte[] label = [0x6C, 0x62, 0x6C];

        using var p = CkmSp800108KdfParams.Counter(CKM.CKM_AES_CMAC)
            .IterationCounter(widthInBits: 16, littleEndian: true)
            .OptionalCounter(widthInBits: 8, littleEndian: false)
            .ByteArray(label)
            .DkmLength(Sp800108DkmLengthMethod.SumOfSegments, widthInBits: 64, littleEndian: true)
            .KeyHandle(spliceKey)
            .Build();

        var s = (CK_SP800_108_KDF_PARAMS)p.ToMarshalableStructure();
        Assert.Equal((ulong)CKM.CKM_AES_CMAC, (ulong)s.PrfType);
        Assert.Equal(5UL, (ulong)s.NumberOfDataParams);
        Assert.NotEqual(IntPtr.Zero, s.DataParams);

        // [0] iteration counter — 16-bit little-endian
        var iter = Param(s.DataParams, 0);
        Assert.Equal(IterationVariable, (ulong)iter.Type);
        var icf = UnmanagedMemory.Read<CK_SP800_108_COUNTER_FORMAT>(iter.Value);
        Assert.True(icf.LittleEndian);
        Assert.Equal(16UL, (ulong)icf.WidthInBits);

        // [1] optional counter — 8-bit big-endian
        var opt = Param(s.DataParams, 1);
        Assert.Equal(OptionalCounter, (ulong)opt.Type);
        var ocf = UnmanagedMemory.Read<CK_SP800_108_COUNTER_FORMAT>(opt.Value);
        Assert.False(ocf.LittleEndian);
        Assert.Equal(8UL, (ulong)ocf.WidthInBits);

        // [2] byte array
        var ba = Param(s.DataParams, 2);
        Assert.Equal(ByteArrayTag, (ulong)ba.Type);
        Assert.Equal(label, UnmanagedMemory.Read(ba.Value, label.Length));

        // [3] DKM length — sum-of-segments, 64-bit little-endian
        var dkm = Param(s.DataParams, 3);
        Assert.Equal(DkmLengthTag, (ulong)dkm.Type);
        var df = UnmanagedMemory.Read<CK_SP800_108_DKM_LENGTH_FORMAT>(dkm.Value);
        Assert.Equal((ulong)Sp800108DkmLengthMethod.SumOfSegments, (ulong)df.DkmLengthMethod);
        Assert.True(df.LittleEndian);
        Assert.Equal(64UL, (ulong)df.WidthInBits);

        // [4] key handle — value is a CK_OBJECT_HANDLE holding the spliced key's handle
        var kh = Param(s.DataParams, 4);
        Assert.Equal(KeyHandleTag, (ulong)kh.Type);
        Assert.Equal((ulong)UnmanagedMemory.NativeULongSize, (ulong)kh.ValueLen);
        Assert.Equal(spliceKey, ReadHandle(kh.Value));
    }

    [Fact]
    public void DoublePipeline_MarshalsCounterParamsStruct()
    {
        using var p = CkmSp800108KdfParams.DoublePipeline(CKM.CKM_SHA256_HMAC)
            .IterationCounter().ByteArray([1, 2]).DkmLength(Sp800108DkmLengthMethod.SumOfKeys).Build();

        var s = (CK_SP800_108_KDF_PARAMS)p.ToMarshalableStructure();
        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfType);
        Assert.Equal(3UL, (ulong)s.NumberOfDataParams);
    }

    [Fact]
    public void Build_WithNoSegments_Throws() =>
        Assert.Throws<InvalidOperationException>(() => CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC).Build());

    [Fact]
    public void WithIV_OnNonFeedbackMode_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC).WithIV([1, 2, 3]));
        Assert.Throws<InvalidOperationException>(() => CkmSp800108KdfParams.DoublePipeline(CKM.CKM_SHA256_HMAC).WithIV([1, 2, 3]));
    }

    [Fact]
    public void CounterModeHmac_Preset_HasNoAdditionalDerivedKeys()
    {
        using var p = CkmSp800108KdfParams.CounterModeHmac(CKM.CKM_SHA256_HMAC, [1], [2]);
        Assert.Empty(p.AdditionalDerivedKeys);
        var s = (CK_SP800_108_KDF_PARAMS)p.ToMarshalableStructure();
        Assert.Equal(0UL, (ulong)s.AdditionalDerivedKeys);
        Assert.Equal(IntPtr.Zero, s.AdditionalDerivedKeysPtr);
    }

    [Fact]
    public void AdditionalDerivedKeys_MarshalTemplatesAndReadBackHandles()
    {
        var templateA = new List<ObjectAttribute> { new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_AES) };
        var templateB = new List<ObjectAttribute> { new(CKA.CKA_VALUE_LEN, 16UL) };
        try
        {
            using var p = CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC)
                .IterationCounter().ByteArray([1]).DkmLength(Sp800108DkmLengthMethod.SumOfKeys)
                .AddDerivedKey(templateA)
                .AddDerivedKey(templateB)
                .Build();

            var s = (CK_SP800_108_KDF_PARAMS)p.ToMarshalableStructure();
            Assert.Equal(2UL, (ulong)s.AdditionalDerivedKeys);
            Assert.NotEqual(IntPtr.Zero, s.AdditionalDerivedKeysPtr);

            int dkSize = UnmanagedMemory.SizeOf(typeof(CK_DERIVED_KEY));
            var dk0 = UnmanagedMemory.Read<CK_DERIVED_KEY>(s.AdditionalDerivedKeysPtr);
            var dk1 = UnmanagedMemory.Read<CK_DERIVED_KEY>(s.AdditionalDerivedKeysPtr + dkSize);
            Assert.Equal(2UL, (ulong)dk0.AttributeCount);
            Assert.Equal(1UL, (ulong)dk1.AttributeCount);
            Assert.NotEqual(IntPtr.Zero, dk0.Template);
            Assert.NotEqual(IntPtr.Zero, dk1.Template);

            // Slots start at CK_INVALID_HANDLE (0) until the token populates them.
            Assert.Equal(new ulong[] { 0, 0 }, p.AdditionalDerivedKeys);

            // Simulate the token writing the derived handles into the phKey slots.
            WriteHandle(dk0.Key, 0x111);
            WriteHandle(dk1.Key, 0x222);
            Assert.Equal(new ulong[] { 0x111, 0x222 }, p.AdditionalDerivedKeys);
        }
        finally
        {
            foreach (var a in templateA) a.Dispose();
            foreach (var a in templateB) a.Dispose();
        }
    }

    [Fact]
    public void AfterDispose_AccessorsThrow()
    {
        var p = CkmSp800108KdfParams.CounterModeHmac(CKM.CKM_SHA256_HMAC, default, default);
        p.Dispose();
        Assert.Throws<ObjectDisposedException>(() => p.ToMarshalableStructure());
        Assert.Throws<ObjectDisposedException>(() => _ = p.AdditionalDerivedKeys);
        Assert.Null(Record.Exception(p.Dispose)); // idempotent
    }
}
