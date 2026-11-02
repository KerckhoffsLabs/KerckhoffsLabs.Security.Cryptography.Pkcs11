using System.Buffers.Binary;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

#pragma warning disable KLPKCS11009 // CKM_AES_CTR: the policy gate is not what these tests are about

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// <see cref="CkmAesCtrParams"/>: <c>CK_AES_CTR_PARAMS</c> is <c>{ CK_ULONG ulCounterBits; CK_BYTE cb[16]; }</c>
/// (PKCS#11 v3.2 §6.11.2), so the descriptor checks both fields before anything reaches a token and
/// marshals the counter width at the platform's <c>CK_ULONG</c> width.
/// </summary>
public sealed unsafe class CkmAesCtrParamsTests
{
    private static readonly byte[] Block = [0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF];

    [Theory]
    [InlineData(1)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    public void CounterBits_InRange_IsAccepted(int counterBits)
        => Assert.NotNull(new CkmAesCtrParams(counterBits, Block));

    [Theory]
    [InlineData(int.MinValue)]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(129)]
    [InlineData(int.MaxValue)]
    public void CounterBits_OutOfRange_Throws(int counterBits)
        => Assert.Equal("counterBits", Assert.Throws<ArgumentOutOfRangeException>(() => new CkmAesCtrParams(counterBits, Block)).ParamName);

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(17)]
    [InlineData(32)]
    public void CounterBlock_NotExactly16Bytes_Throws(int length)
        => Assert.Equal("counterBlock", Assert.Throws<ArgumentException>(() => new CkmAesCtrParams(128, new byte[length])).ParamName);

    [Fact]
    public void CounterBlock_Of16Bytes_IsAccepted()
        => Assert.NotNull(new CkmAesCtrParams(128, new byte[16]));

    [Fact]
    public void CounterBitsOnlyOverload_Is128()
    {
        using var scope = new MechanismParameterScope();
        var s = new CkmAesCtrParams(Block).BuildMarshalable(scope).Read<CK_AES_CTR_PARAMS>();
        Assert.Equal(128UL, (ulong)s.CounterBits);
    }

    // CK_ULONG is 32 bits on Windows and 64 on LP64: the block starts right after ulCounterBits either way.
    [Theory]
    [InlineData(1)]
    [InlineData(32)]
    [InlineData(128)]
    public void BuildMarshalable_WritesTheCounterBitsAtCkUlongWidthThenTheBlock(int counterBits)
    {
        using var scope = new MechanismParameterScope();
        var block = new CkmAesCtrParams(counterBits, Block).BuildMarshalable(scope);

        int word = UnmanagedMemory.NativeULongSize;
        Assert.Equal(word + 16, block.Length);
        Assert.Equal(Pkcs11Marshal.SizeOf<CK_AES_CTR_PARAMS>(), block.Length);

        byte[] bytes = new ReadOnlySpan<byte>((void*)block.Pointer, block.Length).ToArray();
        ulong written = word == 8
            ? BinaryPrimitives.ReadUInt64LittleEndian(bytes)
            : BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        Assert.Equal((ulong)counterBits, written);
        Assert.Equal(Block, bytes[word..]);
    }

    [Fact]
    public void Block_IsCopied_SoLaterChangesToTheCallersBufferAreIgnored()
    {
        byte[] caller = (byte[])Block.Clone();
        var p = new CkmAesCtrParams(128, caller);
        Array.Clear(caller);

        using var scope = new MechanismParameterScope();
        var s = p.BuildMarshalable(scope).Read<CK_AES_CTR_PARAMS>();
        Assert.Equal(Block, ((ReadOnlySpan<byte>)s.Cb).ToArray());
    }

    [Fact]
    public void OneInstance_MarshalsRepeatedly_AndBacksSeveralMechanisms()
    {
        var p = new CkmAesCtrParams(64, Block);
        var a = new Mechanism(CKM.CKM_AES_CTR, p);
        var b = new Mechanism(CKM.CKM_AES_CTR, p);
        Assert.Equal(CKM.CKM_AES_CTR, a.Type);
        Assert.Equal(CKM.CKM_AES_CTR, b.Type);

        for (int i = 0; i < 2; i++)
        {
            using var scope = new MechanismParameterScope();
            Assert.Equal(64UL, (ulong)p.BuildMarshalable(scope).Read<CK_AES_CTR_PARAMS>().CounterBits);
        }
    }

    [Fact]
    public void Mechanism_AcceptsTheParameter()
    {
        var mechanism = new Mechanism(CKM.CKM_AES_CTR, new CkmAesCtrParams(128, Block));
        Assert.Equal(CKM.CKM_AES_CTR, mechanism.Type);
    }
}
