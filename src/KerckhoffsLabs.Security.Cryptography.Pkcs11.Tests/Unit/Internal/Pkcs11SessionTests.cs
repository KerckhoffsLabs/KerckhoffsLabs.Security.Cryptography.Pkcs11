using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Hermetic tests for the parts of <see cref="Pkcs11Session"/> that run before/around the native
/// call — disposed guards, argument-null guards, and CKR-&gt;exception mapping — driven through a
/// <see cref="FakeModule"/> behind the real loader. The crypto itself is covered by the Integration suite.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionTests
{
    private const ulong SessionId = 11;

    private sealed class SessionFake : SessionTestModule
    {
        public CKR SessionInfoRv = CKR.CKR_OK;
        public CKR GenerateRandomRv = CKR.CKR_OK;

        protected override CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info) => SessionInfoRv;
        protected override CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData) => GenerateRandomRv;
        protected override CKR C_Logout(NativeCULong session) => CKR.CKR_OK;
        protected override CKR C_SessionCancel(NativeCULong session, NativeCULong flags) => CKR.CKR_OK;
    }

    private static Mechanism AesGen() => new(CKM.CKM_AES_KEY_GEN);

    // === Construction =====================================================

    [Fact]
    public void Ctor_NullLibrary_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new Pkcs11Session(null!, SessionId));

    [Fact]
    public void Ctor_InvalidHandle_Throws()
    {
        using var fake = new SessionFake();
        Assert.Throws<ArgumentException>(() => fake.CreateSession(0UL));
    }

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
            ("CancelOperations", s => s.CancelOperations(0)),
            ("CancelFunction", s => s.CancelFunction()),
            ("GetFunctionStatus", s => s.GetFunctionStatus()),
            ("GenerateRandom", s => s.GenerateRandom(8)),
            ("SupportsMechanism", s => s.SupportsMechanism(CKM.CKM_AES_GCM)),
        ];

        using var fake = new SessionFake();
        foreach (var (name, op) in ops)
        {
            var session = fake.CreateSession(SessionId);
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
        using var fake = new SessionFake();
        using var s = fake.CreateSession(SessionId);
        Assert.Throws<ArgumentNullException>(() => s.Login(CKU.CKU_USER, null!));
    }

    [Fact]
    public void InitPin_NullPin_Throws()
    {
        using var fake = new SessionFake();
        using var s = fake.CreateSession(SessionId);
        Assert.Throws<ArgumentNullException>(() => s.InitPin(null!));
    }

    [Fact]
    public void SetPin_NullArgs_Throw()
    {
        using var fake = new SessionFake();
        using var s = fake.CreateSession(SessionId);
        using var pin = new SecurePin("1234");
        Assert.Throws<ArgumentNullException>(() => s.SetPin(null!, pin));
        Assert.Throws<ArgumentNullException>(() => s.SetPin(pin, null!));
    }

    [Fact]
    public void LoginUser_NullArgs_Throw()
    {
        using var fake = new SessionFake();
        using var s = fake.CreateSession(SessionId);
        using var pin = new SecurePin("1234");
        Assert.Throws<ArgumentNullException>(() => s.LoginUser(CKU.CKU_USER, null!, "alice"));
        Assert.Throws<ArgumentNullException>(() => s.LoginUser(CKU.CKU_USER, pin, null!));
    }

    [Fact]
    public void SetOperationState_NullState_Throws()
    {
        using var fake = new SessionFake();
        using var s = fake.CreateSession(SessionId);
        Assert.Throws<ArgumentNullException>(() =>
            s.SetOperationState(null!, ObjectHandle.Invalid, ObjectHandle.Invalid));
    }

    [Fact]
    public void SeedRandom_NullSeed_Throws()
    {
        using var fake = new SessionFake();
        using var s = fake.CreateSession(SessionId);
        Assert.Throws<ArgumentNullException>(() => s.SeedRandom((byte[])null!));
    }

    // Each operation null-guards its mechanism before touching the token.
    [Fact]
    public void Operations_NullMechanism_Throw()
    {
        using var fake = new SessionFake();
        using var s = fake.CreateSession(SessionId);
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
        // The key-generation mechanism is a placeholder for every operation; argument validation, not the
        // policy's operation check, is under test.
        using var fake = new SessionFake();
        using var s = fake.CreateSession(SessionId, policy: CryptoPolicy.AllowInsecure);
        var mech = AesGen();
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
        using var fake = new SessionFake { SessionInfoRv = CKR.CKR_SESSION_HANDLE_INVALID };
        using var s = fake.CreateSession(SessionId);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.GetSessionInfo());
    }

    [Fact]
    public void GenerateRandom_Ok_ReturnsRequestedLength()
    {
        using var fake = new SessionFake();
        using var s = fake.CreateSession(SessionId);
        Assert.Equal(8, s.GenerateRandom(8).Length);
    }

    [Fact]
    public void GenerateRandom_Error_Throws()
    {
        using var fake = new SessionFake { GenerateRandomRv = CKR.CKR_DEVICE_ERROR };
        using var s = fake.CreateSession(SessionId);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.GenerateRandom(8));
    }

    [Fact]
    public void Logout_And_CancelOperations_Ok_DoNotThrow()
    {
        using var fake = new SessionFake();
        using var s = fake.CreateSession(SessionId);
        Assert.Null(Record.Exception(() =>
        {
            s.Logout();
            s.CancelOperations(0);
        }));
    }

    // === Secure-defaults gate (the session's crypto policy check) ============================
    // SecureOnlyPolicy's evaluation is mechanism-based, not operation-based, so routing every
    // insecure mechanism through Digest exercises each rejection arm.

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
        using var fake = new SessionFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(insecure);
        Assert.Throws<CryptoPolicyViolationException>(() => s.Digest(mech, new byte[1]));
    }

    // === Two-call buffer-probe paths (hermetic: the fake supplies size then bytes) ===========

    private sealed class CryptoFake : SessionTestModule
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

        private CKR TwoCall(NativeBuffer<byte> outBuf, ref NativeCULong outLen)
        {
            // NULL-buffer probe (Sign/Digest report the size on the first call).
            if (outBuf.IsNull) { outLen = (NativeCULong)Output.Length; return ProbeRv; }
            // Too-small buffer (Encrypt/Decrypt size to the input first, then retry on this).
            Span<byte> output = outBuf.Span;
            if (output.Length < Output.Length) { outLen = (NativeCULong)Output.Length; return CKR.CKR_BUFFER_TOO_SMALL; }
            int n = SecondLen ?? Output.Length;
            Output.AsSpan(0, Math.Min(n, output.Length)).CopyTo(output);
            outLen = (NativeCULong)n;
            return FinalRv;
        }

        protected override CKR C_DigestInit(NativeCULong session, CK_MECHANISM mechanism) => InitRv;
        protected override CKR C_Digest(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> digest, ref NativeCULong digestLen) => TwoCall(digest, ref digestLen);
        protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen) => TwoCall(signature, ref signatureLen);
        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        protected override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen) => TwoCall(encryptedData, ref encryptedDataLen);
        protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        protected override CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, NativeBuffer<byte> data, ref NativeCULong dataLen) => TwoCall(data, ref dataLen);
        protected override CKR C_GenerateKey(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, ref NativeCULong key)
        { key = (NativeCULong)GeneratedKeyId; return GenerateKeyRv; }
        protected override CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
        { info.State = (NativeCULong)(ulong)SessionState; return CKR.CKR_OK; }
        protected override CKR C_VerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        protected override CKR C_Verify(NativeCULong session, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) => VerifyRv;
        protected override CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[] template, ref NativeCULong objectId)
        { objectId = (NativeCULong)CreatedObjectId; return CKR.CKR_OK; }
        protected override CKR C_DestroyObject(NativeCULong session, NativeCULong objectId) => CKR.CKR_OK;
        protected override CKR C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size)
        { size = (NativeCULong)ObjectSizeBytes; return CKR.CKR_OK; }
    }

    [Fact]
    public void Digest_Ok_ReturnsProbedBytes()
    {
        using var fake = new CryptoFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256);
        Assert.Equal(fake.Output, s.Digest(mech, [1, 2, 3]));
    }

    [Fact]
    public void Sign_Ok_ReturnsProbedBytes()
    {
        using var fake = new CryptoFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        Assert.Equal(fake.Output, s.Sign(mech, ObjectHandle.Invalid, [1, 2, 3]));
    }

    [Fact]
    public void Encrypt_Ok_ReturnsProbedBytes()
    {
        using var fake = new CryptoFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        Assert.Equal(fake.Output, s.Encrypt(mech, ObjectHandle.Invalid, [1, 2, 3]));
    }

    [Fact]
    public void Decrypt_Ok_ReturnsProbedBytes()
    {
        using var fake = new CryptoFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        Assert.Equal(fake.Output, s.Decrypt(mech, ObjectHandle.Invalid, [1, 2, 3]));
    }

    [Fact]
    public void Digest_SecondCallReportsFewerBytes_ResizesDown()
    {
        using var fake = new CryptoFake { SecondLen = 2 }; // probe says 4, data call fills 2
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256);
        Assert.Equal(new byte[] { 0xAA, 0xBB }, s.Digest(mech, [1]));
    }

    // An ECDSA signature's length is not known up front, so it is asked for first; that query can fail.
    [Fact]
    public void Sign_LengthQueryError_Throws()
    {
        using var fake = new CryptoFake { ProbeRv = CKR.CKR_FUNCTION_FAILED };
        using var s = fake.CreateSession(SessionId);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.Sign(new Mechanism(CKM.CKM_ECDSA_SHA256), new ObjectHandle(1), [1]));
    }

    // A digest's length is known, so there is no probe to fail: the first call fills the output.
    [Theory]
    [InlineData("init")]
    [InlineData("final")]
    public void Digest_NativeError_Throws(string failingCall)
    {
        using var fake = new CryptoFake
        {
            InitRv = failingCall == "init" ? CKR.CKR_MECHANISM_INVALID : CKR.CKR_OK,
            ProbeRv = failingCall == "probe" ? CKR.CKR_FUNCTION_FAILED : CKR.CKR_OK,
            FinalRv = failingCall == "final" ? CKR.CKR_DEVICE_ERROR : CKR.CKR_OK,
        };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.Digest(mech, [1]));
    }

    [Fact]
    public void GenerateKey_Ok_ReturnsHandleFromToken()
    {
        using var fake = new CryptoFake { GeneratedKeyId = 0x1234 };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_KEY_GEN);
        Assert.Equal(0x1234UL, s.GenerateKey(mech, []).ObjectId);
    }

    [Fact]
    public void GenerateKey_Error_Throws()
    {
        using var fake = new CryptoFake { GenerateKeyRv = CKR.CKR_TEMPLATE_INCONSISTENT };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_KEY_GEN);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.GenerateKey(mech, []));
    }

    [Fact]
    public void GetSessionInfo_Ok_DecodesState()
    {
        using var fake = new CryptoFake { SessionState = CKS.CKS_RW_USER_FUNCTIONS };
        using var s = fake.CreateSession(SessionId);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, s.GetSessionInfo().State);
    }

    // === Verify (CKR_OK = valid, CKR_SIGNATURE_INVALID = false, else throw) =================

    [Fact]
    public void Verify_Ok_SetsValidTrue()
    {
        using var fake = new CryptoFake { VerifyRv = CKR.CKR_OK };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        s.Verify(mech, ObjectHandle.Invalid, new byte[] { 1 }, new byte[] { 2 }, out bool valid);
        Assert.True(valid);
    }

    [Fact]
    public void Verify_SignatureInvalid_SetsValidFalse()
    {
        using var fake = new CryptoFake { VerifyRv = CKR.CKR_SIGNATURE_INVALID };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        s.Verify(mech, ObjectHandle.Invalid, new byte[] { 1 }, new byte[] { 2 }, out bool valid);
        Assert.False(valid);
    }

    [Fact]
    public void Verify_OtherError_Throws()
    {
        using var fake = new CryptoFake { VerifyRv = CKR.CKR_DEVICE_ERROR };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.Verify(mech, ObjectHandle.Invalid, new byte[] { 1 }, new byte[] { 2 }, out _));
    }

    // === Objects ============================================================================

    [Fact]
    public void CreateObject_Ok_ReturnsHandleFromToken()
    {
        using var fake = new CryptoFake { CreatedObjectId = 0x55 };
        using var s = fake.CreateSession(SessionId);
        Assert.Equal(0x55UL, s.CreateObject([]).ObjectId);
    }

    [Fact]
    public void DestroyObject_Ok_DoesNotThrow()
    {
        using var fake = new CryptoFake();
        using var s = fake.CreateSession(SessionId);
        Assert.Null(Record.Exception(() => s.DestroyObject(new ObjectHandle(1))));
    }

    [Fact]
    public void GetObjectSize_Ok_ReturnsSize()
    {
        using var fake = new CryptoFake { ObjectSizeBytes = 512 };
        using var s = fake.CreateSession(SessionId);
        Assert.Equal(512UL, s.GetObjectSize(new ObjectHandle(1)));
    }
}
