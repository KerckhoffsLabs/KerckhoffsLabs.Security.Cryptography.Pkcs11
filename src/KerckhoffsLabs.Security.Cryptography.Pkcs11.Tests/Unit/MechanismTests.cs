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
        using var mech = new Mechanism((ulong)CKM.CKM_AES_KEY_GEN);
        Assert.Equal((ulong)CKM.CKM_AES_KEY_GEN, mech.Type);
        Assert.Null(mech.Parameters);
    }

    [Fact]
    public void Ctor_RawUlong_ByteArrayParameter_SetsType()
    {
        using var mech = new Mechanism((ulong)CKM.CKM_AES_GCM, [0x01, 0x02, 0x03]);
        Assert.Equal((ulong)CKM.CKM_AES_GCM, mech.Type);
    }

    [Fact]
    public void Ctor_RawUlong_MechanismParameters_SetsTypeAndKeepsParameter()
    {
        var p = new CkmPqcSignParams();
        using var mech = new Mechanism((ulong)CKM.CKM_ML_DSA, p);
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
        using var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        using var mech = new Mechanism(CKM.CKM_AES_GCM, p);
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
        using var mech = new Mechanism(CKM.CKM_AES_CBC, iv);
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
        using var mech = new Mechanism(CKM.CKM_AES_CBC, iv);
        using var scope = new MechanismParameterScope();

        CryptographicOperations.ZeroMemory(iv);
        CK_MECHANISM marshalled = mech.Marshal(scope, out _);

        Assert.Equal(expected, UnmanagedMemory.Read(marshalled.Parameter, expected.Length));
    }

    // Reaches the byte[] constructor with nothing in it — a mechanism that takes no parameter is the
    // only way to do that without tripping the weak-mechanism gate.
    [Fact]
    public void Marshal_EmptyByteArrayParameter_IsNullPointerAndZeroLength()
    {
        using var mech = new Mechanism(CKM.CKM_AES_KEY_GEN, []);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM marshalled = mech.Marshal(scope, out _);

        Assert.Equal(IntPtr.Zero, marshalled.Parameter);
        Assert.Equal(0UL, (ulong)marshalled.ParameterLen);
    }

    [Fact]
    public void Marshal_NoParameter_IsNullPointerAndZeroLength()
    {
        using var mech = new Mechanism(CKM.CKM_AES_KEY_GEN);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM marshalled = mech.Marshal(scope, out _);

        Assert.Equal((ulong)CKM.CKM_AES_KEY_GEN, (ulong)marshalled.Mechanism);
        Assert.Equal(IntPtr.Zero, marshalled.Parameter);
        Assert.Equal(0UL, (ulong)marshalled.ParameterLen);
    }

    // Disposing a mechanism must NOT dispose the descriptor it was built with — the inversion of the
    // old ownership rule. The descriptor is shareable managed state, so the common loop shape
    // (one descriptor, a fresh `using var` mechanism per iteration) has to leave it usable. Before
    // this branch the first mechanism disposed took the parameters with it.
    [Fact]
    public void DisposingMechanism_LeavesTheParametersUsable()
    {
        using var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);

        new Mechanism(CKM.CKM_AES_GCM, p).Dispose();

        using var second = new Mechanism(CKM.CKM_AES_GCM, p);
        using var scope = new MechanismParameterScope();
        CK_MECHANISM marshalled = second.Marshal(scope, out object? mechParams);
        Assert.Equal((ulong)CKM.CKM_AES_GCM, (ulong)marshalled.Mechanism);
        Assert.NotEqual(IntPtr.Zero, marshalled.Parameter);
        Assert.NotNull(mechParams);
    }

    [Fact]
    public void Marshal_AfterMechanismDisposed_Throws()
    {
        using var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        var mech = new Mechanism(CKM.CKM_AES_GCM, p);
        mech.Dispose();
        using var scope = new MechanismParameterScope();

        Assert.Throws<ObjectDisposedException>(() => mech.Marshal(scope, out _));
    }

    [Fact]
    public void AbsorbOutput_NullMarshalledParams_IsNoOp()
    {
        using var mech = new Mechanism(CKM.CKM_AES_KEY_GEN);
        using var scope = new MechanismParameterScope();

        mech.Marshal(scope, out object? mechParams);

        // Parameterless mechanisms marshal to a null struct; absorbing it must do nothing rather
        // than throw, because every converted session site absorbs unconditionally.
        Assert.Null(mechParams);
        Assert.Null(Record.Exception(() => mech.AbsorbOutput(mechParams)));
    }
}
