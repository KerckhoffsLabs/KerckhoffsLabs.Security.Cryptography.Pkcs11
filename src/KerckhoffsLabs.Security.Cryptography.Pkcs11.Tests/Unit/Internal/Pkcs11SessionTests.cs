using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Hermetic tests for the parts of <see cref="Pkcs11Session"/> that run before/around the native
/// call — disposed guards, argument-null guards, and CKR-&gt;exception mapping — driven through
/// <see cref="ILowLevelPkcs11Library"/>. The crypto itself is covered by the Integration suite.
/// </summary>
public sealed class Pkcs11SessionTests
{
    private const ulong SessionId = 11;

    private sealed class SessionFake : FakeLowLevelPkcs11Library
    {
        public CKR SessionInfoRv = CKR.CKR_OK;
        public CKR GenerateRandomRv = CKR.CKR_OK;

        public override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;
        public override CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info) => SessionInfoRv;
        public override CKR C_GenerateRandom(NativeCULong session, byte[] randomData, NativeCULong randomLen) => GenerateRandomRv;
        public override CKR C_Logout(NativeCULong session) => CKR.CKR_OK;
        public override CKR C_SessionCancel(NativeCULong session, NativeCULong flags) => CKR.CKR_OK;
    }

    private static Pkcs11Session NewSession() => new(new SessionFake(), SessionId);
    private static Pkcs11Session NewSession(SessionFake fake) => new(fake, SessionId);

    private static Mechanism AesGen() => new(CKM.CKM_AES_KEY_GEN);

    // === Construction =====================================================

    [Fact]
    public void Ctor_NullLibrary_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new Pkcs11Session(null!, SessionId));

    [Fact]
    public void Ctor_InvalidHandle_Throws() =>
        Assert.Throws<ArgumentException>(() => new Pkcs11Session(new SessionFake(), 0UL));

    // === Disposed guards (no-arg core methods with a confirmed _disposed check) =============
    // One [Fact] with a local table — Pkcs11Session is internal, so it can't appear in a public
    // [MemberData] signature.

    [Fact]
    public void Operations_AfterDispose_ThrowObjectDisposed()
    {
        (string Name, Action<Pkcs11Session> Op)[] ops =
        [
            ("GetSessionInfo", s => s.GetSessionInfo()),
            ("GetOperationState", s => s.GetOperationState()),
            ("Logout", s => s.Logout()),
            ("CloseSession", s => s.CloseSession()),
            ("CancelOperations", s => s.CancelOperations(0)),
            ("CancelFunction", s => s.CancelFunction()),
            ("GetFunctionStatus", s => s.GetFunctionStatus()),
            ("GenerateRandom", s => s.GenerateRandom(8)),
        ];

        foreach (var (name, op) in ops)
        {
            var session = NewSession();
            session.Dispose();
            Exception? ex = Record.Exception(() => op(session));
            Assert.True(ex is ObjectDisposedException,
                $"{name}: expected ObjectDisposedException, got {ex?.GetType().Name ?? "none"}");
        }
    }

    // === Argument-null guards (fire before any native call) =================================

    [Fact]
    public void Login_NullPin_Throws()
    {
        var s = NewSession();
        Assert.Throws<ArgumentNullException>(() => s.Login(CKU.CKU_USER, null!));
    }

    [Fact]
    public void InitPin_NullPin_Throws()
    {
        var s = NewSession();
        Assert.Throws<ArgumentNullException>(() => s.InitPin(null!));
    }

    [Fact]
    public void SetPin_NullArgs_Throw()
    {
        var s = NewSession();
        using var pin = new SecurePin("1234");
        Assert.Throws<ArgumentNullException>(() => s.SetPin(null!, pin));
        Assert.Throws<ArgumentNullException>(() => s.SetPin(pin, null!));
    }

    [Fact]
    public void LoginUser_NullArgs_Throw()
    {
        var s = NewSession();
        using var pin = new SecurePin("1234");
        Assert.Throws<ArgumentNullException>(() => s.LoginUser(CKU.CKU_USER, null!, "alice"));
        Assert.Throws<ArgumentNullException>(() => s.LoginUser(CKU.CKU_USER, pin, null!));
    }

    [Fact]
    public void SetOperationState_NullState_Throws()
    {
        var s = NewSession();
        Assert.Throws<ArgumentNullException>(() =>
            s.SetOperationState(null!, ObjectHandle.Invalid, ObjectHandle.Invalid));
    }

    [Fact]
    public void SeedRandom_NullSeed_Throws()
    {
        var s = NewSession();
        Assert.Throws<ArgumentNullException>(() => s.SeedRandom((byte[])null!));
    }

    // Each operation null-guards its mechanism before touching the token.
    [Fact]
    public void Operations_NullMechanism_Throw()
    {
        var s = NewSession();
        ObjectHandle h = ObjectHandle.Invalid;
        Assert.Throws<ArgumentNullException>(() => s.Sign(null!, h, new byte[1]));
        Assert.Throws<ArgumentNullException>(() => s.Encrypt(null!, h, new byte[1]));
        Assert.Throws<ArgumentNullException>(() => s.Decrypt(null!, h, new byte[1]));
        Assert.Throws<ArgumentNullException>(() => s.Digest(null!, new byte[1]));
        Assert.Throws<ArgumentNullException>(() => s.DigestKey(null!, h));
        Assert.Throws<ArgumentNullException>(() => s.DeriveKey(null!, h, []));
        Assert.Throws<ArgumentNullException>(() => s.GenerateKey(null!, []));
        Assert.Throws<ArgumentNullException>(() => s.WrapKey(null!, h, h));
        Assert.Throws<ArgumentNullException>(() => s.UnwrapKey(null!, h, new byte[1], []));
    }

    // Byte[] overloads null-guard their data/attributes too.
    [Fact]
    public void Operations_NullData_Throw()
    {
        var s = NewSession();
        using var mech = AesGen();
        ObjectHandle h = ObjectHandle.Invalid;
        Assert.Throws<ArgumentNullException>(() => s.Encrypt(mech, h, (byte[])null!));
        Assert.Throws<ArgumentNullException>(() => s.Decrypt(mech, h, (byte[])null!));
        Assert.Throws<ArgumentNullException>(() => s.Digest(mech, (byte[])null!));
        Assert.Throws<ArgumentNullException>(() => s.UnwrapKey(mech, h, (byte[])null!, []));
    }

    // === Fake-driven success / error mapping ================================================

    [Fact]
    public void GetSessionInfo_Error_Throws()
    {
        var fake = new SessionFake { SessionInfoRv = CKR.CKR_SESSION_HANDLE_INVALID };
        var s = NewSession(fake);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.GetSessionInfo());
    }

    [Fact]
    public void GenerateRandom_Ok_ReturnsRequestedLength()
    {
        var s = NewSession();
        Assert.Equal(8, s.GenerateRandom(8).Length);
    }

    [Fact]
    public void GenerateRandom_Error_Throws()
    {
        var fake = new SessionFake { GenerateRandomRv = CKR.CKR_DEVICE_ERROR };
        var s = NewSession(fake);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.GenerateRandom(8));
    }

    [Fact]
    public void Logout_And_CancelOperations_Ok_DoNotThrow()
    {
        var s = NewSession();
        s.Logout();
        s.CancelOperations(0);
    }
}
