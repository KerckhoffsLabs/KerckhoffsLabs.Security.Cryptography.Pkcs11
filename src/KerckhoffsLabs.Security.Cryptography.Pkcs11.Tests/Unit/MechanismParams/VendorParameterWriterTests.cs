using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// The vendor parameter writer exists so a caller never has to reason about PKCS#11 struct layout,
/// which means the writer itself has to get the layout exactly right — and a mistake there is silent,
/// producing a plausible block the token misreads.
/// </summary>
/// <remarks>
/// So these tests use the library's own interop structs as the oracle: for a given field list, the
/// bytes the writer emits must equal, byte for byte, what marshalling the real
/// <c>[PackedForPkcs11]</c> struct produces. The struct layouts are already validated against the
/// PKCS#11 headers on six platforms in CI, so agreeing with them is the strongest available evidence
/// — far stronger than asserting offsets this test computed by the same reasoning as the code.
/// </remarks>
public sealed class VendorParameterWriterTests
{
    private sealed class Described(Action<Pkcs11ParameterWriter> describe) : VendorMechanismParameters
    {
        protected override void Describe(Pkcs11ParameterWriter writer) => describe(writer);
    }

    /// <summary>Bytes the real marshalling path produces for an interop struct.</summary>
    private static byte[] RealBytes<T>(in T value) where T : unmanaged
    {
        using var scope = new MechanismParameterScope();
        int size = UnmanagedMemory.SizeOf<T>();
        IntPtr block = scope.Allocate(size);
        UnmanagedMemory.Write(block, in value);

        byte[] bytes = new byte[size];
        UnmanagedMemory.Read(block, bytes);
        return bytes;
    }

    /// <summary>Bytes the vendor writer produces for a described field list.</summary>
    private static byte[] WrittenBytes(Action<Pkcs11ParameterWriter> describe)
    {
        using var scope = new MechanismParameterScope();
        var block = (Pkcs11ParameterBlock)new Described(describe).BuildMarshalable(scope);

        byte[] bytes = new byte[block.Length];
        UnmanagedMemory.Read(block.Pointer, bytes);
        return bytes;
    }

    // Three CK_ULONGs, no padding anywhere — the base case.
    [Fact]
    public void ThreeCkULongs_MatchRsaPssParams()
    {
        var real = new CK_RSA_PKCS_PSS_PARAMS
        {
            HashAlg = CKM.CKM_SHA256.ToCULong(),
            Mgf = (NativeCULong)(ulong)CKG.CKG_MGF1_SHA256,
            Len = (NativeCULong)32,
        };

        Assert.Equal(
            RealBytes(in real),
            WrittenBytes(w => w
                .CkULong((ulong)CKM.CKM_SHA256)
                .CkULong((ulong)CKG.CKG_MGF1_SHA256)
                .CkULong(32)));
    }

    // The case that decides whether the layout rule is right: a one-byte field between two
    // CK_ULONGs. Naturally aligned, the second CK_ULONG cannot follow the bool immediately and the
    // struct gains trailing padding; packed, the whole thing is 8+1+8 with neither. Get this wrong
    // and every vendor struct containing a CK_BBOOL is silently misaligned from that field on.
    [Fact]
    public void CkULong_Bool_CkULong_MatchesDkmLengthFormat()
    {
        var real = new CK_SP800_108_DKM_LENGTH_FORMAT
        {
            DkmLengthMethod = (NativeCULong)1,
            LittleEndian = true,
            WidthInBits = (NativeCULong)64,
        };

        Assert.Equal(
            RealBytes(in real),
            WrittenBytes(w => w.CkULong(1).CkBBool(true).CkULong(64)));
    }

    // A CK_BBOOL that is false must still occupy its slot: a writer that skipped falsey fields would
    // pass the test above and shift every following field here.
    [Fact]
    public void FalseBool_StillOccupiesItsSlot()
    {
        var real = new CK_SP800_108_DKM_LENGTH_FORMAT
        {
            DkmLengthMethod = (NativeCULong)2,
            LittleEndian = false,
            WidthInBits = (NativeCULong)32,
        };

        Assert.Equal(
            RealBytes(in real),
            WrittenBytes(w => w.CkULong(2).CkBBool(false).CkULong(32)));
    }

    // An inline fixed array — the counter block lives in the struct, not behind a pointer.
    [Fact]
    public void InlineBytes_MatchAesCtrParams()
    {
        byte[] cb = [.. Enumerable.Range(1, 16).Select(i => (byte)i)];
        var real = new CK_AES_CTR_PARAMS { CounterBits = (NativeCULong)128 };
        cb.CopyTo(((Span<byte>)real.Cb));

        Assert.Equal(
            RealBytes(in real),
            WrittenBytes(w => w.CkULong(128).InlineBytes(cb, 16)));
    }

    // A different inline width, to catch a writer that hardcoded 16.
    [Fact]
    public void InlineBytes_MatchRc2CbcParams()
    {
        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8];
        var real = new CK_RC2_CBC_PARAMS { EffectiveBits = (NativeCULong)64 };
        iv.CopyTo(((Span<byte>)real.Iv));

        Assert.Equal(
            RealBytes(in real),
            WrittenBytes(w => w.CkULong(64).InlineBytes(iv, 8)));
    }

    // Short input is zero-padded to the declared width rather than shortening the field.
    [Fact]
    public void InlineBytes_ShorterThanTheField_IsZeroPadded()
    {
        var real = new CK_RC2_CBC_PARAMS { EffectiveBits = (NativeCULong)64 };
        new byte[] { 0xAA, 0xBB }.CopyTo(((Span<byte>)real.Iv));

        Assert.Equal(
            RealBytes(in real),
            WrittenBytes(w => w.CkULong(64).InlineBytes([0xAA, 0xBB], 8)));
    }

    // A pointer field, pinned with NULL so the bytes are deterministic. CK_EDDSA_PARAMS leads with a
    // CK_BBOOL and puts the length before the pointer, so this also catches a writer that assumed
    // fields come in pointer-then-length order.
    [Fact]
    public void NullPointerAndLength_MatchEddsaParams()
    {
        var real = new CK_EDDSA_PARAMS
        {
            PhFlag = true,
            ContextDataLen = (NativeCULong)0,
            ContextData = IntPtr.Zero,
        };

        Assert.Equal(
            RealBytes(in real),
            WrittenBytes(w => w.CkBBool(true).CkULong(0).NullPointer()));
    }

    // Buffer() must write the bytes somewhere the token can reach and store that address in the
    // field — not the bytes themselves, and not a dangling pointer.
    [Fact]
    public void Buffer_StoresAPointerToTheCopiedBytes()
    {
        byte[] payload = [0xDE, 0xAD, 0xBE, 0xEF];

        using var scope = new MechanismParameterScope();
        var block = (Pkcs11ParameterBlock)new Described(w => w.CkULong((ulong)payload.Length).Buffer(payload))
            .BuildMarshalable(scope);

        byte[] bytes = new byte[block.Length];
        UnmanagedMemory.Read(block.Pointer, bytes);

        // The pointer field sits after the CK_ULONG length, and is pointer-wide — reading a fixed 64
        // bits here overruns the whole block on a 32-bit runtime, where CK_ULONG and the pointer are
        // four bytes each.
        IntPtr target = MemoryMarshal.Read<IntPtr>(bytes.AsSpan(UnmanagedMemory.NativeULongSize));
        Assert.NotEqual(IntPtr.Zero, target);

        byte[] pointee = new byte[payload.Length];
        UnmanagedMemory.Read(target, pointee);
        Assert.Equal(payload, pointee);
    }

    /// <summary>An empty buffer is NULL, which is how PKCS#11 spells "absent".</summary>
    [Fact]
    public void EmptyBuffer_IsANullPointer()
    {
        var real = new CK_EDDSA_PARAMS
        {
            PhFlag = false,
            ContextDataLen = (NativeCULong)0,
            ContextData = IntPtr.Zero,
        };

        Assert.Equal(
            RealBytes(in real),
            WrittenBytes(w => w.CkBBool(false).CkULong(0).Buffer(default)));
    }

    // End to end: the block reaches CK_MECHANISM with the vendor mechanism type and the right
    // length, and nothing is absorbed back.
    [Fact]
    public void VendorParameters_ReachCkMechanism()
    {
        const ulong CkmIbmMlDsa = 0x80010036UL; // CKM_VENDOR_DEFINED + 0x10036
        var mech = new Mechanism(CkmIbmMlDsa, new Described(w => w.CkULong(7).CkBBool(true)));
        using var scope = new MechanismParameterScope();

        CK_MECHANISM marshalled = mech.Marshal(scope, out object? marshalledParams);

        Assert.Equal(CkmIbmMlDsa, (ulong)marshalled.Mechanism);
        Assert.NotEqual(IntPtr.Zero, marshalled.Parameter);
        Assert.Equal(
            (ulong)WrittenBytes(w => w.CkULong(7).CkBBool(true)).Length,
            (ulong)marshalled.ParameterLen);
        Assert.NotNull(marshalledParams);
        Assert.Null(Record.Exception(() => mech.AbsorbOutput(marshalledParams)));
    }

    // Descriptors hold managed data only, so one instance can back two mechanisms and each call gets
    // its own block — the same guarantee the built-in parameter types give.
    [Fact]
    public void OneVendorDescriptor_CanBackTwoMechanisms()
    {
        var shared = new Described(w => w.CkULong(3).Buffer([1, 2, 3]));
        var first = new Mechanism(0x80010036UL, shared);
        var second = new Mechanism(0x80010036UL, shared);

        using var scopeA = new MechanismParameterScope();
        using var scopeB = new MechanismParameterScope();
        CK_MECHANISM a = first.Marshal(scopeA, out _);
        CK_MECHANISM b = second.Marshal(scopeB, out _);

        Assert.NotEqual(a.Parameter, b.Parameter);
        Assert.Equal((ulong)a.ParameterLen, (ulong)b.ParameterLen);
    }

    [Fact]
    public void InlineBytes_LongerThanTheField_Throws()
    {
        using var scope = new MechanismParameterScope();
        var p = new Described(w => w.InlineBytes([1, 2, 3], 2));

        Assert.Throws<ArgumentOutOfRangeException>(() => p.BuildMarshalable(scope));
    }
}
