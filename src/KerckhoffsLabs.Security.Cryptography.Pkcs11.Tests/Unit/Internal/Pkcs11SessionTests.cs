using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
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
        Assert.Null(Record.Exception(() =>
        {
            s.Logout();
            s.CancelOperations(0);
        }));
    }

    // === Secure-defaults gate (GuardMechanism) ==============================================
    // GuardMechanism is mechanism-based, not operation-based, so routing every insecure mechanism
    // through Digest exercises each rejection arm.

    [Theory]
    [InlineData(CKM.CKM_RSA_PKCS)]
    [InlineData(CKM.CKM_MD5)]
    [InlineData(CKM.CKM_SHA_1)]
    [InlineData(CKM.CKM_MD5_RSA_PKCS)]
    [InlineData(CKM.CKM_SHA1_RSA_PKCS)]
    [InlineData(CKM.CKM_SHA1_RSA_PKCS_PSS)]
    [InlineData(CKM.CKM_DES_CBC)]
    [InlineData(CKM.CKM_DES3_CBC)]
    [InlineData(CKM.CKM_DES_MAC)]
    [InlineData(CKM.CKM_DES3_MAC)]
    [InlineData(CKM.CKM_DES_KEY_GEN)]
    [InlineData(CKM.CKM_DES3_KEY_GEN)]
    [InlineData(CKM.CKM_AES_ECB)]
    [InlineData(CKM.CKM_AES_CBC)]
    [InlineData(CKM.CKM_AES_CBC_PAD)]
    [InlineData(CKM.CKM_AES_CFB128)]
    [InlineData(CKM.CKM_DES3_ECB_ENCRYPT_DATA)]
    [InlineData(CKM.CKM_RC4)]
    [InlineData(CKM.CKM_RC2_CBC)]
    [InlineData(CKM.CKM_SEED_CBC)]
    [InlineData(CKM.CKM_MD2)]
    [InlineData(CKM.CKM_RIPEMD160)]
    [InlineData(CKM.CKM_SHA_1_HMAC)]
    [InlineData(CKM.CKM_ECDSA_SHA1)]
    [InlineData(CKM.CKM_RSA_X_509)]
    [InlineData(CKM.CKM_CAST128_CBC)]
    [InlineData(CKM.CKM_RC5_CBC)]
    [InlineData(CKM.CKM_BLOWFISH_CBC)]
    [InlineData(CKM.CKM_SKIPJACK_WRAP)]
    public void InsecureMechanism_IsRejected(CKM insecure)
    {
        var s = NewSession();
        using var mech = new Mechanism(insecure);
        Assert.Throws<InsecureOperationException>(() => s.Digest(mech, new byte[1]));
    }

    // === Two-call buffer-probe paths (hermetic: the fake supplies size then bytes) ===========

    private sealed class CryptoFake : FakeLowLevelPkcs11Library
    {
        public byte[] Output = [0xAA, 0xBB, 0xCC, 0xDD];
        public CKR InitRv = CKR.CKR_OK, ProbeRv = CKR.CKR_OK, FinalRv = CKR.CKR_OK;
        public int? SecondLen;            // when set, the data call reports fewer bytes -> resize
        public CKR GenerateKeyRv = CKR.CKR_OK;
        public ulong GeneratedKeyId = 99;
        public CKS SessionState = CKS.CKS_RW_USER_FUNCTIONS;
        public CKR VerifyRv = CKR.CKR_OK;
        public ulong CreatedObjectId = 77;
        public ulong ObjectSizeBytes = 256;

        private CKR TwoCall(byte[]? outBuf, ref NativeCULong outLen)
        {
            // Null-buffer probe (Sign/Digest report the size on the first call).
            if (outBuf is null) { outLen = (NativeCULong)Output.Length; return ProbeRv; }
            // Too-small buffer (Encrypt/Decrypt size to the input first, then retry on this).
            if (outBuf.Length < Output.Length) { outLen = (NativeCULong)Output.Length; return CKR.CKR_BUFFER_TOO_SMALL; }
            int n = SecondLen ?? Output.Length;
            Array.Copy(Output, outBuf, Math.Min(n, outBuf.Length));
            outLen = (NativeCULong)n;
            return FinalRv;
        }

        public override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;
        public override CKR C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism) => InitRv;
        public override CKR C_Digest(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? digest, ref NativeCULong digestLen) => TwoCall(digest, ref digestLen);
        public override CKR C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        public override CKR C_Sign(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? signature, ref NativeCULong signatureLen) => TwoCall(signature, ref signatureLen);
        public override CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        public override CKR C_Encrypt(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? encryptedData, ref NativeCULong encryptedDataLen) => TwoCall(encryptedData, ref encryptedDataLen);
        public override CKR C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        public override CKR C_Decrypt(NativeCULong session, byte[] encryptedData, NativeCULong encryptedDataLen, byte[]? data, ref NativeCULong dataLen) => TwoCall(data, ref dataLen);
        public override CKR C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong key)
        { key = (NativeCULong)GeneratedKeyId; return GenerateKeyRv; }
        public override CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
        { info.State = (NativeCULong)(ulong)SessionState; return CKR.CKR_OK; }
        public override CKR C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        public override CKR C_Verify(NativeCULong session, byte[] data, NativeCULong dataLen, byte[] signature, NativeCULong signatureLen) => VerifyRv;
        public override CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong objectId)
        { objectId = (NativeCULong)CreatedObjectId; return CKR.CKR_OK; }
        public override CKR C_DestroyObject(NativeCULong session, NativeCULong objectId) => CKR.CKR_OK;
        public override CKR C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size)
        { size = (NativeCULong)ObjectSizeBytes; return CKR.CKR_OK; }
    }

    private static Pkcs11Session NewSession(CryptoFake fake) => new(fake, SessionId);

    [Fact]
    public void Digest_Ok_ReturnsProbedBytes()
    {
        var fake = new CryptoFake();
        var s = NewSession(fake);
        using var mech = new Mechanism(CKM.CKM_SHA256);
        Assert.Equal(fake.Output, s.Digest(mech, [1, 2, 3]));
    }

    [Fact]
    public void Sign_Ok_ReturnsProbedBytes()
    {
        var fake = new CryptoFake();
        var s = NewSession(fake);
        using var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        Assert.Equal(fake.Output, s.Sign(mech, ObjectHandle.Invalid, [1, 2, 3]));
    }

    [Fact]
    public void Encrypt_Ok_ReturnsProbedBytes()
    {
        var fake = new CryptoFake();
        var s = NewSession(fake);
        using var mech = new Mechanism(CKM.CKM_AES_GCM);
        Assert.Equal(fake.Output, s.Encrypt(mech, ObjectHandle.Invalid, [1, 2, 3]));
    }

    [Fact]
    public void Decrypt_Ok_ReturnsProbedBytes()
    {
        var fake = new CryptoFake();
        var s = NewSession(fake);
        using var mech = new Mechanism(CKM.CKM_AES_GCM);
        Assert.Equal(fake.Output, s.Decrypt(mech, ObjectHandle.Invalid, [1, 2, 3]));
    }

    [Fact]
    public void Digest_SecondCallReportsFewerBytes_ResizesDown()
    {
        var fake = new CryptoFake { SecondLen = 2 }; // probe says 4, data call fills 2
        var s = NewSession(fake);
        using var mech = new Mechanism(CKM.CKM_SHA256);
        Assert.Equal(new byte[] { 0xAA, 0xBB }, s.Digest(mech, [1]));
    }

    [Theory]
    [InlineData("init")]
    [InlineData("probe")]
    [InlineData("final")]
    public void Digest_NativeError_Throws(string failingCall)
    {
        var fake = new CryptoFake
        {
            InitRv = failingCall == "init" ? CKR.CKR_MECHANISM_INVALID : CKR.CKR_OK,
            ProbeRv = failingCall == "probe" ? CKR.CKR_FUNCTION_FAILED : CKR.CKR_OK,
            FinalRv = failingCall == "final" ? CKR.CKR_DEVICE_ERROR : CKR.CKR_OK,
        };
        var s = NewSession(fake);
        using var mech = new Mechanism(CKM.CKM_SHA256);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.Digest(mech, [1]));
    }

    [Fact]
    public void GenerateKey_Ok_ReturnsHandleFromToken()
    {
        var fake = new CryptoFake { GeneratedKeyId = 0x1234 };
        var s = NewSession(fake);
        using var mech = new Mechanism(CKM.CKM_AES_KEY_GEN);
        Assert.Equal(0x1234UL, s.GenerateKey(mech, []).ObjectId);
    }

    [Fact]
    public void GenerateKey_Error_Throws()
    {
        var fake = new CryptoFake { GenerateKeyRv = CKR.CKR_TEMPLATE_INCONSISTENT };
        var s = NewSession(fake);
        using var mech = new Mechanism(CKM.CKM_AES_KEY_GEN);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.GenerateKey(mech, []));
    }

    [Fact]
    public void GetSessionInfo_Ok_DecodesState()
    {
        var fake = new CryptoFake { SessionState = CKS.CKS_RW_USER_FUNCTIONS };
        var s = NewSession(fake);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, s.GetSessionInfo().State);
    }

    // === Verify (CKR_OK = valid, CKR_SIGNATURE_INVALID = false, else throw) =================

    [Fact]
    public void Verify_Ok_SetsValidTrue()
    {
        var s = NewSession(new CryptoFake { VerifyRv = CKR.CKR_OK });
        using var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        s.Verify(mech, ObjectHandle.Invalid, new byte[] { 1 }, new byte[] { 2 }, out bool valid);
        Assert.True(valid);
    }

    [Fact]
    public void Verify_SignatureInvalid_SetsValidFalse()
    {
        var s = NewSession(new CryptoFake { VerifyRv = CKR.CKR_SIGNATURE_INVALID });
        using var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        s.Verify(mech, ObjectHandle.Invalid, new byte[] { 1 }, new byte[] { 2 }, out bool valid);
        Assert.False(valid);
    }

    [Fact]
    public void Verify_OtherError_Throws()
    {
        var s = NewSession(new CryptoFake { VerifyRv = CKR.CKR_DEVICE_ERROR });
        using var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.Verify(mech, ObjectHandle.Invalid, new byte[] { 1 }, new byte[] { 2 }, out _));
    }

    // === Objects ============================================================================

    [Fact]
    public void CreateObject_Ok_ReturnsHandleFromToken()
    {
        var s = NewSession(new CryptoFake { CreatedObjectId = 0x55 });
        Assert.Equal(0x55UL, s.CreateObject([]).ObjectId);
    }

    [Fact]
    public void DestroyObject_Ok_DoesNotThrow()
    {
        var s = NewSession(new CryptoFake());
        Assert.Null(Record.Exception(() => s.DestroyObject(new ObjectHandle(1))));
    }

    [Fact]
    public void GetObjectSize_Ok_ReturnsSize()
    {
        var s = NewSession(new CryptoFake { ObjectSizeBytes = 512 });
        Assert.Equal(512UL, s.GetObjectSize(new ObjectHandle(1)));
    }
}
