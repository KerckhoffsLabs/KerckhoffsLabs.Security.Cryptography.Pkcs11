using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Verifies that <see cref="CkmRc2Params"/> / <see cref="CkmRc2CbcParams"/> marshal the RC2
/// effective-key-bits and the inline 8-byte IV correctly through the packed-struct marshaller. The
/// bundled SoftHSM implements no RC2, so this round-trip is the primary correctness check on the
/// parameter structs without a token.
/// </summary>
public sealed class Rc2ParamsMarshalTests
{
    [Fact]
    public void CkmRc2Params_MarshalsEffectiveBits()
    {
        using var p = new CkmRc2Params(64);
        using var scope = new MechanismParameterScope();
        var s = (CK_RC2_PARAMS)p.BuildMarshalable(scope);

        int size = UnmanagedMemory.SizeOf<CK_RC2_PARAMS>();
        IntPtr mem = UnmanagedMemory.Allocate(size);
        try
        {
            UnmanagedMemory.Write(mem, (object)s);
            var back = UnmanagedMemory.Read<CK_RC2_PARAMS>(mem);
            Assert.Equal(64UL, (ulong)back.EffectiveBits);
        }
        finally { UnmanagedMemory.Free(ref mem); }
    }

    [Fact]
    public void CkmRc2CbcParams_MarshalsEffectiveBitsAndInlineIv()
    {
        byte[] iv = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        using var p = new CkmRc2CbcParams(128, iv);
        using var scope = new MechanismParameterScope();
        var s = (CK_RC2_CBC_PARAMS)p.BuildMarshalable(scope);

        int size = UnmanagedMemory.SizeOf<CK_RC2_CBC_PARAMS>();
        IntPtr mem = UnmanagedMemory.Allocate(size);
        try
        {
            UnmanagedMemory.Write(mem, (object)s);
            var back = UnmanagedMemory.Read<CK_RC2_CBC_PARAMS>(mem);
            Assert.Equal(128UL, (ulong)back.EffectiveBits);
            Assert.True(iv.AsSpan().SequenceEqual(back.Iv), "8-byte inline IV did not round-trip");
        }
        finally { UnmanagedMemory.Free(ref mem); }
    }

    [Fact]
    public void CkmRc2CbcParams_RejectsNon8ByteIv() =>
        Assert.Throws<ArgumentException>(() => new CkmRc2CbcParams(128, new byte[7]));
}
