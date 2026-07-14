using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

// These tests drive the gated legacy mechanisms/hashes on purpose (the AllowInsecure gate is the
// behaviour under test), so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Hermetic coverage for session lifecycle (login/PIN/operation-state/random) success and
/// error-mapping paths, plus the security-critical <see cref="Pkcs11Session.AllowInsecureScope"/>
/// gate. The fake captures the marshalled arguments so the tests assert both the CKR-&gt;exception
/// mapping and that PIN/username/seed bytes are passed through correctly — neither of which the
/// Integration suite can observe.
/// </summary>
public sealed class Pkcs11SessionLifecycleTests
{
    private const ulong SessionId = 11;

    private sealed class LifecycleFake : FakeLowLevelPkcs11Library
    {
        public CKR LoginRv = CKR.CKR_OK, LoginUserRv = CKR.CKR_OK, InitPinRv = CKR.CKR_OK,
            SetPinRv = CKR.CKR_OK, SeedRv = CKR.CKR_OK, GenRandomRv = CKR.CKR_OK,
            GetOpStateRv = CKR.CKR_OK, SetOpStateRv = CKR.CKR_OK, GenerateKeyRv = CKR.CKR_OK,
            FunctionStatusRv = CKR.CKR_FUNCTION_NOT_PARALLEL, CancelFunctionRv = CKR.CKR_FUNCTION_NOT_PARALLEL;

        public CKU? CapturedUserType;
        public byte[]? CapturedPin;
        public byte[]? CapturedUsername;
        public byte[]? CapturedSeed;
        public byte[]? CapturedOpState;
        public ulong CapturedEncKey, CapturedAuthKey;
        public byte[] OperationState = [0x01, 0x02, 0x03, 0x04];
        public ulong GeneratedKeyId = 0x42;

        public override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;
        public override CKR C_Logout(NativeCULong session) => CKR.CKR_OK;

        public override CKR C_Login(NativeCULong session, CKU userType, byte[] pin, NativeCULong pinLen)
        { CapturedUserType = userType; CapturedPin = pin[..(int)pinLen]; return LoginRv; }

        public override CKR C_LoginUser(NativeCULong session, CKU userType, byte[] pin, NativeCULong pinLen, byte[] username, NativeCULong usernameLen)
        { CapturedUserType = userType; CapturedPin = pin[..(int)pinLen]; CapturedUsername = username[..(int)usernameLen]; return LoginUserRv; }

        public override CKR C_InitPIN(NativeCULong session, byte[] pin, NativeCULong pinLen)
        { CapturedPin = pin[..(int)pinLen]; return InitPinRv; }

        public override CKR C_SetPIN(NativeCULong session, byte[] oldPin, NativeCULong oldPinLen, byte[] newPin, NativeCULong newPinLen)
            => SetPinRv;

        public override CKR C_SeedRandom(NativeCULong session, byte[] seed, NativeCULong seedLen)
        { CapturedSeed = seed[..(int)seedLen]; return SeedRv; }

        public override CKR C_GenerateRandom(NativeCULong session, byte[] randomData, NativeCULong randomLen)
        { for (int i = 0; i < (int)randomLen; i++) randomData[i] = (byte)(i + 1); return GenRandomRv; }

        public override CKR C_GetOperationState(NativeCULong session, byte[]? operationState, ref NativeCULong operationStateLen)
        {
            if (operationState is null) { operationStateLen = (NativeCULong)OperationState.Length; return GetOpStateRv; }
            Array.Copy(OperationState, operationState, OperationState.Length);
            operationStateLen = (NativeCULong)OperationState.Length;
            return GetOpStateRv;
        }

        public override CKR C_SetOperationState(NativeCULong session, byte[] operationState, NativeCULong operationStateLen, NativeCULong encryptionKey, NativeCULong authenticationKey)
        { CapturedOpState = operationState[..(int)operationStateLen]; CapturedEncKey = (ulong)encryptionKey; CapturedAuthKey = (ulong)authenticationKey; return SetOpStateRv; }

        public override CKR C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong key)
        { key = (NativeCULong)GeneratedKeyId; return GenerateKeyRv; }

        public override CKR C_GetFunctionStatus(NativeCULong session) => FunctionStatusRv;
        public override CKR C_CancelFunction(NativeCULong session) => CancelFunctionRv;
    }

    private static Pkcs11Session NewSession(LifecycleFake fake) => new(fake, SessionId);
    private static Pkcs11Session NewSession() => new(new LifecycleFake(), SessionId);

    // === Login / LoginUser ==================================================

    [Fact]
    public void Login_Ok_PassesUserTypeAndPin()
    {
        var fake = new LifecycleFake();
        var s = NewSession(fake);
        using var pin = new SecurePin("1234");

        s.Login(CKU.CKU_USER, pin);

        Assert.Equal(CKU.CKU_USER, fake.CapturedUserType);
        Assert.Equal("1234"u8.ToArray(), fake.CapturedPin);
    }

    [Fact]
    public void Login_Error_Throws()
    {
        var s = NewSession(new LifecycleFake { LoginRv = CKR.CKR_PIN_INCORRECT });
        using var pin = new SecurePin("0000");
        Assert.ThrowsAny<Pkcs11Exception>(() => s.Login(CKU.CKU_USER, pin));
    }

    [Fact]
    public void LoginUser_Ok_EncodesUsernameUtf8()
    {
        var fake = new LifecycleFake();
        var s = NewSession(fake);
        using var pin = new SecurePin("1234");

        s.LoginUser(CKU.CKU_USER, pin, "operator-1");

        Assert.Equal(Encoding.UTF8.GetBytes("operator-1"), fake.CapturedUsername);
        Assert.Equal("1234"u8.ToArray(), fake.CapturedPin);
    }

    [Fact]
    public void LoginUser_EmptyUsername_Throws()
    {
        var s = NewSession();
        using var pin = new SecurePin("1234");
        Assert.Throws<ArgumentException>(() => s.LoginUser(CKU.CKU_USER, pin, ""));
    }

    [Fact]
    public void LoginUser_Error_Throws()
    {
        var s = NewSession(new LifecycleFake { LoginUserRv = CKR.CKR_FUNCTION_NOT_SUPPORTED });
        using var pin = new SecurePin("1234");
        Assert.ThrowsAny<Pkcs11Exception>(() => s.LoginUser(CKU.CKU_USER, pin, "alice"));
    }

    // === PIN management =====================================================

    [Fact]
    public void InitPin_Ok_PassesPin()
    {
        var fake = new LifecycleFake();
        var s = NewSession(fake);
        using var pin = new SecurePin("9876");

        s.InitPin(pin);

        Assert.Equal("9876"u8.ToArray(), fake.CapturedPin);
    }

    [Fact]
    public void InitPin_Error_Throws()
    {
        var s = NewSession(new LifecycleFake { InitPinRv = CKR.CKR_USER_NOT_LOGGED_IN });
        using var pin = new SecurePin("9876");
        Assert.ThrowsAny<Pkcs11Exception>(() => s.InitPin(pin));
    }

    [Fact]
    public void SetPin_Ok_DoesNotThrow()
    {
        var s = NewSession();
        using var oldPin = new SecurePin("1111");
        using var newPin = new SecurePin("2222");
        Assert.Null(Record.Exception(() => s.SetPin(oldPin, newPin)));
    }

    [Fact]
    public void SetPin_Error_Throws()
    {
        var s = NewSession(new LifecycleFake { SetPinRv = CKR.CKR_PIN_INVALID });
        using var oldPin = new SecurePin("1111");
        using var newPin = new SecurePin("2222");
        Assert.ThrowsAny<Pkcs11Exception>(() => s.SetPin(oldPin, newPin));
    }

    // === Operation state ====================================================

    [Fact]
    public void GetOperationState_Ok_ReturnsProbedBytes()
    {
        var s = NewSession(new LifecycleFake { OperationState = [5, 6, 7] });
        Assert.Equal(new byte[] { 5, 6, 7 }, s.GetOperationState());
    }

    [Fact]
    public void GetOperationState_Error_Throws()
    {
        var s = NewSession(new LifecycleFake { GetOpStateRv = CKR.CKR_STATE_UNSAVEABLE });
        Assert.ThrowsAny<Pkcs11Exception>(() => s.GetOperationState());
    }

    [Fact]
    public void SetOperationState_Ok_PassesStateAndKeyHandles()
    {
        var fake = new LifecycleFake();
        var s = NewSession(fake);

        s.SetOperationState([1, 2, 3], new ObjectHandle(7), new ObjectHandle(9));

        Assert.Equal(new byte[] { 1, 2, 3 }, fake.CapturedOpState);
        Assert.Equal(7UL, fake.CapturedEncKey);
        Assert.Equal(9UL, fake.CapturedAuthKey);
    }

    [Fact]
    public void SetOperationState_Error_Throws()
    {
        var s = NewSession(new LifecycleFake { SetOpStateRv = CKR.CKR_SAVED_STATE_INVALID });
        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.SetOperationState([1, 2, 3], ObjectHandle.Invalid, ObjectHandle.Invalid));
    }

    // === Random =============================================================

    [Fact]
    public void GenerateRandom_Span_FillsBuffer()
    {
        var s = NewSession();
        Span<byte> buffer = stackalloc byte[4];
        int written = s.GenerateRandom(buffer);
        Assert.Equal(4, written);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, buffer.ToArray());
    }

    [Fact]
    public void GenerateRandom_Span_Empty_ReturnsZero()
    {
        var s = NewSession();
        Assert.Equal(0, s.GenerateRandom([]));
    }

    [Fact]
    public void SeedRandom_Ok_PassesSeed()
    {
        var fake = new LifecycleFake();
        var s = NewSession(fake);
        s.SeedRandom([0xDE, 0xAD]);
        Assert.Equal([0xDE, 0xAD], fake.CapturedSeed);
    }

    [Fact]
    public void SeedRandom_Error_Throws()
    {
        var s = NewSession(new LifecycleFake { SeedRv = CKR.CKR_RANDOM_SEED_NOT_SUPPORTED });
        Assert.ThrowsAny<Pkcs11Exception>(() => s.SeedRandom([1]));
    }

    // === Legacy parallel-function stubs (always map their CKR to an exception) ===

    [Fact]
    public void GetFunctionStatus_Throws()
    {
        var s = NewSession();
        Assert.ThrowsAny<Pkcs11Exception>(() => s.GetFunctionStatus());
    }

    [Fact]
    public void CancelFunction_Throws()
    {
        var s = NewSession();
        Assert.ThrowsAny<Pkcs11Exception>(() => s.CancelFunction());
    }

    // === AllowInsecure / AllowInsecureScope =================================

    [Fact]
    public void AllowInsecure_Setter_RoundTrips()
    {
        var s = NewSession();
        Assert.False(s.AllowInsecure);
        s.AllowInsecure = true;
        Assert.True(s.AllowInsecure);
        s.AllowInsecure = false;
        Assert.False(s.AllowInsecure);
    }

    [Fact]
    public void AllowInsecureScope_PermitsInsecureMechanism_ThenRestores()
    {
        var fake = new LifecycleFake { GeneratedKeyId = 7 };
        var s = NewSession(fake);

        // Gated by default.
        using (var mech = new Mechanism(CKM.CKM_DES_KEY_GEN))
            Assert.Throws<InsecureOperationException>(() => s.GenerateKey(mech, []));

        // Permitted inside the scope.
        using (s.AllowInsecureScope())
        {
            Assert.True(s.AllowInsecure);
            using var mech = new Mechanism(CKM.CKM_DES_KEY_GEN);
            Assert.Equal(7UL, s.GenerateKey(mech, []).ObjectId);
        }

        // Restored to gated after the scope.
        Assert.False(s.AllowInsecure);
        using (var mech = new Mechanism(CKM.CKM_DES_KEY_GEN))
            Assert.Throws<InsecureOperationException>(() => s.GenerateKey(mech, []));
    }

    [Fact]
    public void AllowInsecureScope_NestsLifo()
    {
        var s = NewSession();
        Assert.False(s.AllowInsecure);
        using (s.AllowInsecureScope())
        {
            Assert.True(s.AllowInsecure);
            using (s.AllowInsecureScope())
                Assert.True(s.AllowInsecure);
            // Inner lease restores to its captured "previous" (true), not to false.
            Assert.True(s.AllowInsecure);
        }
        Assert.False(s.AllowInsecure);
    }

    [Fact]
    public void AllowInsecure_AfterDispose_Throws()
    {
        var s = NewSession();
        s.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = s.AllowInsecure);
        Assert.Throws<ObjectDisposedException>(() => s.AllowInsecure = true);
        Assert.Throws<ObjectDisposedException>(() => s.AllowInsecureScope());
    }
}
