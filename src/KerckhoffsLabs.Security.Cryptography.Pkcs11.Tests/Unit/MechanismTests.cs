using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

// CKM_AES_CBC appears here only as a realistic mechanism whose parameter is a raw IV block, which is
// what the raw-block constructor marshals. Nothing is encrypted and no token is involved, so the
// crypto-policy check never runs; the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// Covers the Mechanism constructors and marshalling, for standard and vendor types alike. No token
// needed — these only build the CK_MECHANISM value.
public sealed class MechanismTests
{
    [Fact]
    public void Ctor_NoParameter_SetsType()
    {
        var mech = new Mechanism(CKM.CKM_AES_KEY_GEN);
        Assert.Equal(CKM.CKM_AES_KEY_GEN, mech.Type);
        Assert.Null(mech.Parameters);
    }

    // A vendor mechanism the CKM enum has no member for. CKM is ulong-backed like CK_MECHANISM_TYPE, so
    // the cast names it exactly.
    private const CKM CkmIbmEthDerive = (CKM)0x80070002UL;  // CKM_VENDOR_DEFINED + 0x70002

    // A vendor type with a raw block is the escape hatch for a vendor mechanism whose parameter this
    // library cannot describe — an opaque or nested block the caller lays out themselves. Asserting the
    // type alone would not catch a block that never reached the scope, which is the failure a caller
    // would see as the token rejecting a well-formed parameter.
    [Fact]
    public void Marshal_VendorTypeWithByteArrayParameter_CarriesBothTheTypeAndTheBlock()
    {
        byte[] block = [.. Enumerable.Range(0, 24).Select(i => (byte)(0xD0 + i))];
        var mech = new Mechanism(CkmIbmEthDerive, block);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM marshalled = mech.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        Assert.Equal(CkmIbmEthDerive, mech.Type);
        Assert.Equal((ulong)CkmIbmEthDerive, (ulong)marshalled.Mechanism);
        Assert.Equal((ulong)block.Length, (ulong)marshalled.ParameterLen);
        Assert.NotEqual(IntPtr.Zero, marshalled.Parameter);
        Assert.Equal(block, UnmanagedMemory.Read(marshalled.Parameter, block.Length));

        // An opaque block has no output fields, so there is nothing to absorb.
        Assert.Null(mechParams);
    }

    // Aliasing the caller's array would go unnoticed until a caller zeroized their block and the token
    // silently received all zeroes.
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
    public void Ctor_MechanismParameters_SetsTypeAndKeepsParameter()
    {
        var p = new CkmPqcSignParams();
        var mech = new Mechanism(CKM.CKM_ML_DSA, p);
        Assert.Equal(CKM.CKM_ML_DSA, mech.Type);
        Assert.Same(p, mech.Parameters);
    }

    [Fact]
    public void Ctor_NullMechanismParameters_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new Mechanism(CKM.CKM_ML_DSA, (MechanismParameters)null!));

    // Marshal must stay a pure function of (mechanism, scope). One instance can be marshalled twice
    // for two live operations — two sessions, or the same instance passed as both arguments of
    // DecryptVerify — and each needs its own block, so that absorbing one cannot read the other's
    // output. Returning the block rather than caching it on the mechanism is what makes that hold;
    // the signature itself prevents a regression to a cache, and this pins the independence the
    // caller's per-operation locals rely on.
    [Fact]
    public void Marshal_TwiceOnOneInstance_YieldsIndependentBlocks()
    {
        var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        var mech = new Mechanism(CKM.CKM_AES_GCM, p);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM first = mech.Marshal(scope, out Pkcs11ParameterBlock? firstParams);
        CK_MECHANISM second = mech.Marshal(scope, out Pkcs11ParameterBlock? secondParams);

        // Assert.NotNull on a nullable struct returns the value it checked.
        Pkcs11ParameterBlock firstBlock = Assert.NotNull(firstParams);
        Pkcs11ParameterBlock secondBlock = Assert.NotNull(secondParams);
        Assert.NotEqual(first.Parameter, second.Parameter);
        Assert.NotEqual(
            firstBlock.Read<CK_GCM_MESSAGE_PARAMS>().Tag,
            secondBlock.Read<CK_GCM_MESSAGE_PARAMS>().Tag);
    }

    // A byte[] reaches the raw-block constructor through its implicit conversion to a span. A block that
    // never reached the scope would surface only as a token rejecting an empty or garbage parameter, so
    // the block is asserted here directly.
    [Fact]
    public void Marshal_ByteArrayParameter_CopiesTheBytesIntoTheScope()
    {
        byte[] iv = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0];
        var mech = new Mechanism(CKM.CKM_AES_CBC, iv);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM marshalled = mech.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

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

    // An empty array, through the same conversion, is an absent parameter.
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
    // A span cannot be aliased in the byte[] field even in principle, so the copy is the type system's
    // doing. What is not guaranteed, and is what the zeroize below pins, is that the copy happens at
    // construction: a design that captured the source and read it during Marshal would
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
        CK_MECHANISM marshalled = mech.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        Assert.Equal((ulong)CKM.CKM_AES_CBC, (ulong)marshalled.Mechanism);
        Assert.Equal((ulong)expected.Length, (ulong)marshalled.ParameterLen);
        Assert.Equal(expected, UnmanagedMemory.Read(marshalled.Parameter, expected.Length));
        Assert.Null(mechParams);
    }

    // An empty span is an absent parameter, not a pointer to nothing.
    [Fact]
    public void Marshal_EmptySpanParameter_IsNullPointerAndZeroLength()
    {
        ReadOnlySpan<byte> empty = [];
        var mech = new Mechanism(CKM.CKM_AES_KEY_GEN, empty);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM marshalled = mech.Marshal(scope, out _);

        Assert.Equal(IntPtr.Zero, marshalled.Parameter);
        Assert.Equal(0UL, (ulong)marshalled.ParameterLen);
    }

    // What a vendor caller depends on: a type the enum cannot name, and a block that outlives the buffer
    // it was read from.
    [Fact]
    public void Marshal_VendorTypeWithSpanParameter_CarriesBothTheTypeAndTheBlock()
    {
        byte[] source = [.. Enumerable.Range(0, 20).Select(i => (byte)(0x5A + i))];
        byte[] expected = [.. source];
        var mech = new Mechanism(CkmIbmEthDerive, new ReadOnlySpan<byte>(source));
        using var scope = new MechanismParameterScope();

        CryptographicOperations.ZeroMemory(source);
        CK_MECHANISM marshalled = mech.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        Assert.Equal(CkmIbmEthDerive, mech.Type);
        Assert.Equal((ulong)CkmIbmEthDerive, (ulong)marshalled.Mechanism);
        Assert.Equal((ulong)expected.Length, (ulong)marshalled.ParameterLen);
        Assert.Equal(expected, UnmanagedMemory.Read(marshalled.Parameter, expected.Length));
        Assert.Null(mechParams);
    }

    [Fact]
    public void IsVendorDefined_SeparatesVendorTypesFromStandardOnes()
    {
        Assert.True(new Mechanism(CkmIbmEthDerive).IsVendorDefined);
        Assert.True(new Mechanism(CKM.CKM_VENDOR_DEFINED).IsVendorDefined);  // the boundary itself
        Assert.False(new Mechanism(CKM.CKM_AES_KEY_GEN).IsVendorDefined);

        // One below the boundary is still standard, so the comparison cannot be >.
        Assert.False(new Mechanism((CKM)((ulong)CKM.CKM_VENDOR_DEFINED - 1)).IsVendorDefined);
    }

    // Type is the exact value for every mechanism; whether the enum names it is Enum.IsDefined's call.
    [Fact]
    public void Type_IsExact_AndEnumIsDefinedTellsNamedFromUnnamed()
    {
        Assert.Equal(CKM.CKM_AES_GCM, new Mechanism(CKM.CKM_AES_GCM).Type);
        Assert.True(Enum.IsDefined(new Mechanism(CKM.CKM_AES_GCM).Type));

        Assert.Equal(CkmIbmEthDerive, new Mechanism(CkmIbmEthDerive).Type);
        Assert.False(Enum.IsDefined(new Mechanism(CkmIbmEthDerive).Type));
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

        mech.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        // Parameterless mechanisms marshal to a null struct; absorbing it must do nothing rather
        // than throw, because every converted session site absorbs unconditionally.
        Assert.Null(mechParams);
        Assert.Null(Record.Exception(() => mech.AbsorbOutput(mechParams)));
    }

    public static bool NativeULongIs64Bit => UnmanagedMemory.NativeULongSize == sizeof(ulong);
    public static bool NativeULongIs32Bit => UnmanagedMemory.NativeULongSize == sizeof(uint);

    private const CKM WideVendorMechanism = (CKM)0x1_8000_0001UL;

    // Where CK_ULONG is 64 bits a vendor value can exceed 32 bits. CKM holds it exactly, and it reaches
    // the token unchanged.
    [Fact(SkipUnless = nameof(NativeULongIs64Bit), Skip = "CK_ULONG is 32 bits on this platform")]
    public void WideType_IsCarriedExactly_WhereCkUlongIs64Bits()
    {
        var mech = new Mechanism(WideVendorMechanism);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM marshalled = mech.Marshal(scope, out _);

        Assert.Equal(WideVendorMechanism, mech.Type);
        Assert.True(mech.IsVendorDefined);
        Assert.Equal((ulong)WideVendorMechanism, (ulong)marshalled.Mechanism);
    }

    // Where CK_ULONG is 32 bits the same value cannot be sent; it is refused naming the argument, never
    // truncated into a different mechanism.
    [Fact(SkipUnless = nameof(NativeULongIs32Bit), Skip = "CK_ULONG is 64 bits on this platform")]
    public void WideType_IsRefused_WhereCkUlongIs32Bits()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new Mechanism(WideVendorMechanism));
        Assert.Equal("type", ex.ParamName);
    }
}
