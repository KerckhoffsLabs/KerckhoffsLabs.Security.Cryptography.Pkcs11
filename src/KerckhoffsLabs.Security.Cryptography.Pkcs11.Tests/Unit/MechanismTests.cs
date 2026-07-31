using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

// CKM_AES_CBC appears here only as a realistic mechanism whose parameter is a raw IV block, which is
// what the byte[] constructors marshal. Nothing is encrypted and no token is involved, so the
// AllowInsecure gate never runs; the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// Covers the raw-ulong Mechanism constructors (the CKM-typed siblings are exercised throughout the
// crypto suite). No token needed — these only build the CK_MECHANISM value.
public sealed class MechanismTests
{
    [Fact]
    public void Ctor_RawUlong_NoParameter_SetsType()
    {
        var mech = new Mechanism((ulong)CKM.CKM_AES_KEY_GEN);
        Assert.Equal((ulong)CKM.CKM_AES_KEY_GEN, mech.Type);
        Assert.Null(mech.Parameters);
    }

    // A vendor mechanism the CKM enum has no member for. Passing the type as a raw ulong rather than
    // casting an invented enum value is the point of the ulong constructors: the cast would assert the
    // value is a known CKM, which it is not.
    private const ulong CkmIbmEthDerive = 0x80070002UL;  // CKM_VENDOR_DEFINED + 0x70002

    // The ulong+byte[] pairing is the escape hatch for a vendor mechanism whose parameter this library
    // cannot describe — an opaque or nested block the caller lays out themselves. Every other test of
    // the raw path goes through the CKM-typed constructor, so nothing covered the one thing this
    // overload does differently: carry a mechanism value from outside the enum. Asserting the type
    // alone would not have caught a block that never reached the scope, which is the failure a caller
    // would see as the token rejecting a well-formed parameter.
    [Fact]
    public void Marshal_VendorTypeWithByteArrayParameter_CarriesBothTheTypeAndTheBlock()
    {
        byte[] block = [.. Enumerable.Range(0, 24).Select(i => (byte)(0xD0 + i))];
        var mech = new Mechanism(CkmIbmEthDerive, block);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM marshalled = mech.Marshal(scope, out object? mechParams);

        Assert.Equal(CkmIbmEthDerive, mech.Type);
        Assert.Equal(CkmIbmEthDerive, (ulong)marshalled.Mechanism);
        Assert.Equal((ulong)block.Length, (ulong)marshalled.ParameterLen);
        Assert.NotEqual(IntPtr.Zero, marshalled.Parameter);
        Assert.Equal(block, UnmanagedMemory.Read(marshalled.Parameter, block.Length));

        // An opaque block has no output fields, so there is nothing to absorb.
        Assert.Null(mechParams);
    }

    // The defensive copy is a separate line of code in each byte[] constructor, so the CKM-typed
    // sibling's coverage does not extend here: aliasing the caller's array in this one alone would go
    // unnoticed until a caller zeroized their block and the token silently received all zeroes.
    [Fact]
    public void Marshal_VendorTypeWithByteArrayParameter_IgnoresLaterChangesToTheCallersArray()
    {
        byte[] block = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        byte[] expected = [.. block];
        var mech = new Mechanism(CkmIbmEthDerive, block);
        using var scope = new MechanismParameterScope();

        CryptographicOperations.ZeroMemory(block);
        CK_MECHANISM marshalled = mech.Marshal(scope, out _);

        Assert.Equal(expected, UnmanagedMemory.Read(marshalled.Parameter, expected.Length));
    }

    [Fact]
    public void Ctor_RawUlong_MechanismParameters_SetsTypeAndKeepsParameter()
    {
        var p = new CkmPqcSignParams();
        var mech = new Mechanism((ulong)CKM.CKM_ML_DSA, p);
        Assert.Equal((ulong)CKM.CKM_ML_DSA, mech.Type);
        Assert.Same(p, mech.Parameters);
    }

    [Fact]
    public void Ctor_RawUlong_NullMechanismParameters_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new Mechanism((ulong)CKM.CKM_ML_DSA, (MechanismParameters)null!));

    // Marshal must stay a pure function of (mechanism, scope). One instance can be marshalled twice
    // for two live operations — two sessions, or the same instance passed as both arguments of
    // DecryptVerify — and each needs its own block, so that absorbing one cannot read the other's
    // output. Returning the struct rather than caching it on the mechanism is what makes that hold;
    // the signature itself prevents a regression to a cache, and this pins the independence the
    // caller's per-operation locals rely on.
    [Fact]
    public void Marshal_TwiceOnOneInstance_YieldsIndependentBlocks()
    {
        var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        var mech = new Mechanism(CKM.CKM_AES_GCM, p);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM first = mech.Marshal(scope, out object? firstParams);
        CK_MECHANISM second = mech.Marshal(scope, out object? secondParams);

        Assert.NotNull(firstParams);
        Assert.NotNull(secondParams);
        Assert.NotEqual(first.Parameter, second.Parameter);
        Assert.NotEqual(
            ((CK_GCM_MESSAGE_PARAMS)firstParams).Tag,
            ((CK_GCM_MESSAGE_PARAMS)secondParams).Tag);
    }

    // The raw byte[] constructors used to hand Marshal a block their constructor had allocated, so
    // deleting the constructor-time allocation had to route them through the scope instead. Nothing
    // about that is visible to the compiler — a miss would surface only as a token rejecting an empty
    // or garbage parameter — so the block is asserted here directly.
    [Fact]
    public void Marshal_ByteArrayParameter_CopiesTheBytesIntoTheScope()
    {
        byte[] iv = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0];
        var mech = new Mechanism(CKM.CKM_AES_CBC, iv);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM marshalled = mech.Marshal(scope, out object? mechParams);

        Assert.Equal((ulong)CKM.CKM_AES_CBC, (ulong)marshalled.Mechanism);
        Assert.Equal((ulong)iv.Length, (ulong)marshalled.ParameterLen);
        Assert.NotEqual(IntPtr.Zero, marshalled.Parameter);
        Assert.Equal(iv, UnmanagedMemory.Read(marshalled.Parameter, iv.Length));

        // A raw block has no output fields, so there is nothing to absorb.
        Assert.Null(mechParams);
    }

    // The constructor copies the array, so the caller keeps ownership of theirs. Zeroizing an IV
    // buffer after handing it over is good hygiene, and while the block was allocated in the
    // constructor it was also harmless; once Marshal reads the array at call time, aliasing it would
    // turn that hygiene into an all-zero IV silently accepted by the token.
    [Fact]
    public void Marshal_ByteArrayParameter_IgnoresLaterChangesToTheCallersArray()
    {
        byte[] iv = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0];
        byte[] expected = [.. iv];
        var mech = new Mechanism(CKM.CKM_AES_CBC, iv);
        using var scope = new MechanismParameterScope();

        CryptographicOperations.ZeroMemory(iv);
        CK_MECHANISM marshalled = mech.Marshal(scope, out _);

        Assert.Equal(expected, UnmanagedMemory.Read(marshalled.Parameter, expected.Length));
    }

    // Reaches the byte[] constructor with nothing in it — a mechanism that takes no parameter is the
    // only way to do that without tripping the weak-mechanism gate. The cast is load-bearing: an
    // untyped collection expression binds to the ReadOnlySpan<byte> sibling, so without it this would
    // silently stop covering the constructor it is named for.
    [Fact]
    public void Marshal_EmptyByteArrayParameter_IsNullPointerAndZeroLength()
    {
        var mech = new Mechanism(CKM.CKM_AES_KEY_GEN, (byte[])[]);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM marshalled = mech.Marshal(scope, out _);

        Assert.Equal(IntPtr.Zero, marshalled.Parameter);
        Assert.Equal(0UL, (ulong)marshalled.ParameterLen);
    }

    // The span constructor is the one every CBC and CFB operation goes through: those paths hold the
    // IV as a span, and taking an array there made each call copy it twice.
    //
    // Unlike its byte[] siblings, this one cannot alias the caller's buffer even in principle — a span
    // does not fit in the byte[] field, so the copy is the type system's doing rather than a line that
    // could regress. What is not guaranteed, and is what the zeroize below pins, is that the copy
    // happens at construction: a design that captured the source and read it during Marshal would
    // compile just as well and would hand the token whatever the buffer held by then. For a stack
    // span that is not merely stale data but memory the frame no longer owns.
    [Fact]
    public void Marshal_SpanParameter_CopiesTheBytesAtConstruction()
    {
        byte[] source = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0];
        byte[] expected = [.. source];
        var mech = new Mechanism(CKM.CKM_AES_CBC, new ReadOnlySpan<byte>(source));
        using var scope = new MechanismParameterScope();

        CryptographicOperations.ZeroMemory(source);
        CK_MECHANISM marshalled = mech.Marshal(scope, out object? mechParams);

        Assert.Equal((ulong)CKM.CKM_AES_CBC, (ulong)marshalled.Mechanism);
        Assert.Equal((ulong)expected.Length, (ulong)marshalled.ParameterLen);
        Assert.Equal(expected, UnmanagedMemory.Read(marshalled.Parameter, expected.Length));
        Assert.Null(mechParams);
    }

    // An empty span is an absent parameter, not a pointer to nothing — the same distinction the byte[]
    // sibling makes, asserted here because the two constructors build _rawParameter separately.
    [Fact]
    public void Marshal_EmptySpanParameter_IsNullPointerAndZeroLength()
    {
        // Typed local rather than an inline `[]`: the constructor has a byte[] sibling, and naming the
        // type is what keeps this test on the overload it is written for.
        ReadOnlySpan<byte> empty = [];
        var mech = new Mechanism(CKM.CKM_AES_KEY_GEN, empty);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM marshalled = mech.Marshal(scope, out _);

        Assert.Equal(IntPtr.Zero, marshalled.Parameter);
        Assert.Equal(0UL, (ulong)marshalled.ParameterLen);
    }

    // The vendor half of the span pair. It shares Marshal with its CKM sibling but not its own two
    // lines — the mechanism value and the copy — and those are exactly what a vendor caller depends
    // on: a type the enum cannot name, and a block that outlives the buffer it was read from.
    [Fact]
    public void Marshal_VendorTypeWithSpanParameter_CarriesBothTheTypeAndTheBlock()
    {
        byte[] source = [.. Enumerable.Range(0, 20).Select(i => (byte)(0x5A + i))];
        byte[] expected = [.. source];
        var mech = new Mechanism(CkmIbmEthDerive, new ReadOnlySpan<byte>(source));
        using var scope = new MechanismParameterScope();

        CryptographicOperations.ZeroMemory(source);
        CK_MECHANISM marshalled = mech.Marshal(scope, out object? mechParams);

        Assert.Equal(CkmIbmEthDerive, mech.Type);
        Assert.Equal(CkmIbmEthDerive, (ulong)marshalled.Mechanism);
        Assert.Equal((ulong)expected.Length, (ulong)marshalled.ParameterLen);
        Assert.Equal(expected, UnmanagedMemory.Read(marshalled.Parameter, expected.Length));
        Assert.Null(mechParams);
    }

    [Fact]
    public void Marshal_NoParameter_IsNullPointerAndZeroLength()
    {
        var mech = new Mechanism(CKM.CKM_AES_KEY_GEN);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM marshalled = mech.Marshal(scope, out _);

        Assert.Equal((ulong)CKM.CKM_AES_KEY_GEN, (ulong)marshalled.Mechanism);
        Assert.Equal(IntPtr.Zero, marshalled.Parameter);
        Assert.Equal(0UL, (ulong)marshalled.ParameterLen);
    }

    [Fact]
    public void AbsorbOutput_NullMarshalledParams_IsNoOp()
    {
        var mech = new Mechanism(CKM.CKM_AES_KEY_GEN);
        using var scope = new MechanismParameterScope();

        mech.Marshal(scope, out object? mechParams);

        // Parameterless mechanisms marshal to a null struct; absorbing it must do nothing rather
        // than throw, because every converted session site absorbs unconditionally.
        Assert.Null(mechParams);
        Assert.Null(Record.Exception(() => mech.AbsorbOutput(mechParams)));
    }
}
