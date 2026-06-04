using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Verifies that <see cref="CkmSp800108CounterKdfParams"/> marshals the exact NIST SP800-108
/// counter-mode fixed-input sequence the BCL <c>SP800108HmacCounterKdf</c> uses:
/// <c>[i]₃₂ ‖ Label ‖ 0x00 ‖ Context ‖ [L]₃₂</c>. This exercises the unmanaged marshalling without a
/// token (the bundled SoftHSM does not implement the mechanism), so it is the primary correctness
/// check on the data-param construction.
/// </summary>
public sealed class Sp800108CounterKdfParamsTests
{
    private const ulong IterationVariable = 1;
    private const ulong DkmLength = 3;
    private const ulong ByteArray = 4;
    private const ulong SumOfKeys = 1;

    [Fact]
    public void BuildsNistCounterModeFixedInput()
    {
        byte[] label = Encoding.UTF8.GetBytes("lbl");
        byte[] context = Encoding.UTF8.GetBytes("ctx-xyz");

        using var p = new CkmSp800108CounterKdfParams(CKM.CKM_SHA256_HMAC, label, context);
        var kdf = (CK_SP800_108_KDF_PARAMS)p.ToMarshalableStructure();

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)kdf.PrfType);
        Assert.Equal(5UL, (ulong)kdf.NumberOfDataParams);
        Assert.NotEqual(IntPtr.Zero, kdf.DataParams);
        Assert.Equal(0UL, (ulong)kdf.AdditionalDerivedKeys);
        Assert.Equal(IntPtr.Zero, kdf.AdditionalDerivedKeysPtr);

        int elem = UnmanagedMemory.SizeOf(typeof(CK_PRF_DATA_PARAM));
        CK_PRF_DATA_PARAM Param(int i) => UnmanagedMemory.Read<CK_PRF_DATA_PARAM>(kdf.DataParams + (i * elem));

        // [0] iteration variable -> 32-bit big-endian counter format.
        var iter = Param(0);
        Assert.Equal(IterationVariable, (ulong)iter.Type);
        var counter = UnmanagedMemory.Read<CK_SP800_108_COUNTER_FORMAT>(iter.Value);
        Assert.False(counter.LittleEndian);
        Assert.Equal(32UL, (ulong)counter.WidthInBits);

        // [1] Label.
        var lbl = Param(1);
        Assert.Equal(ByteArray, (ulong)lbl.Type);
        Assert.Equal((ulong)label.Length, (ulong)lbl.ValueLen);
        Assert.Equal(label, UnmanagedMemory.Read(lbl.Value, label.Length));

        // [2] 0x00 separator.
        var sep = Param(2);
        Assert.Equal(ByteArray, (ulong)sep.Type);
        Assert.Equal(1UL, (ulong)sep.ValueLen);
        Assert.Equal(new byte[] { 0x00 }, UnmanagedMemory.Read(sep.Value, 1));

        // [3] Context.
        var ctx = Param(3);
        Assert.Equal(ByteArray, (ulong)ctx.Type);
        Assert.Equal((ulong)context.Length, (ulong)ctx.ValueLen);
        Assert.Equal(context, UnmanagedMemory.Read(ctx.Value, context.Length));

        // [4] [L] DKM length -> sum-of-keys, 32-bit big-endian.
        var dkm = Param(4);
        Assert.Equal(DkmLength, (ulong)dkm.Type);
        var dkmFormat = UnmanagedMemory.Read<CK_SP800_108_DKM_LENGTH_FORMAT>(dkm.Value);
        Assert.Equal(SumOfKeys, (ulong)dkmFormat.DkmLengthMethod);
        Assert.False(dkmFormat.LittleEndian);
        Assert.Equal(32UL, (ulong)dkmFormat.WidthInBits);
    }

    [Fact]
    public void EmptyLabelAndContext_StillEmitsFiveParamsWithSeparator()
    {
        using var p = new CkmSp800108CounterKdfParams(CKM.CKM_SHA384_HMAC, label: default, context: default);
        var kdf = (CK_SP800_108_KDF_PARAMS)p.ToMarshalableStructure();
        Assert.Equal(5UL, (ulong)kdf.NumberOfDataParams);

        int elem = UnmanagedMemory.SizeOf(typeof(CK_PRF_DATA_PARAM));
        CK_PRF_DATA_PARAM Param(int i) => UnmanagedMemory.Read<CK_PRF_DATA_PARAM>(kdf.DataParams + (i * elem));

        // Empty label / context: zero length, NULL value; the 0x00 separator is still present.
        Assert.Equal(0UL, (ulong)Param(1).ValueLen);
        Assert.Equal(IntPtr.Zero, Param(1).Value);
        Assert.Equal(1UL, (ulong)Param(2).ValueLen);
        Assert.Equal(0UL, (ulong)Param(3).ValueLen);
        Assert.Equal(IntPtr.Zero, Param(3).Value);
    }
}
