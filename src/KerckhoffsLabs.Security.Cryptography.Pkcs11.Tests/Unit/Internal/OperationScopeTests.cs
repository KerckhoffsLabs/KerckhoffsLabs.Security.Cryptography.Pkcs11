using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// An operation begun with <c>C_*Init</c> stays active on the session until the call that finishes it.
/// If this library throws in between, the operation is cancelled (<c>C_SessionCancel</c>), so the
/// session is not left refusing every later <c>C_*Init</c> of that kind with
/// <c>CKR_OPERATION_ACTIVE</c>; on a module that cannot cancel, that refusal says why.
/// </summary>
public sealed class OperationScopeTests
{
    private const ulong SessionId = 11;

    // The length query succeeded, so the operation is active; the library then refuses the length.
    [Fact]
    public void Sign_ThrowingBetweenCalls_CancelsTheSignOperation_AndKeepsTheOriginalError()
    {
        var fake = new OperationFake { ProbeReports = NativeCULong.MaxValue };

        Assert.Throws<Pkcs11UnclassifiedException>(() => Session(fake).Sign(Ecdsa(), new ObjectHandle(1), "data"u8));

        Assert.Equal([CKF.CKF_SIGN], fake.Cancelled);
    }

    [Fact]
    public void Sign_Succeeding_CancelsNothing()
    {
        var fake = new OperationFake();

        Session(fake).Sign(Ecdsa(), new ObjectHandle(1), "data"u8);

        Assert.Empty(fake.Cancelled);
    }

    // An error return already ended the operation, so the cancel finds nothing: expected, not logged.
    [Fact]
    public void Sign_ModuleErrorOnTheFill_KeepsTheOriginalError_AndLogsNothing()
    {
        var fake = new OperationFake { FillRv = CKR.CKR_DEVICE_ERROR, CancelRv = CKR.CKR_OPERATION_NOT_INITIALIZED };
        var logger = new CapturingLogger();

        var e = Assert.ThrowsAny<Pkcs11Exception>(() => Session(fake, logger).Sign(Ecdsa(), new ObjectHandle(1), "data"u8));

        Assert.Equal(CKR.CKR_DEVICE_ERROR, e.ReturnValue);
        Assert.DoesNotContain(logger.Entries, entry => entry.Level >= LogLevel.Warning);
    }

    // CKR_BUFFER_TOO_SMALL leaves the operation active; the library then refuses the length it asks for.
    [Fact]
    public void Decrypt_ThrowingBetweenCalls_CancelsTheDecryptOperation()
    {
        var fake = new OperationFake { DecryptGrowsBy = 32, TooSmallReports = NativeCULong.MaxValue };

        Assert.Throws<Pkcs11UnclassifiedException>(() => Session(fake).Decrypt(Gcm(), new ObjectHandle(1), new byte[32]));

        Assert.Equal([CKF.CKF_DECRYPT], fake.Cancelled);
    }

    // DecryptVerify had no cancel at all: a failed C_DecryptInit left the verify operation active.
    [Fact]
    public void DecryptVerify_SecondInitFailing_CancelsTheFirstOperation()
    {
        var fake = new OperationFake { DecryptInitRv = CKR.CKR_KEY_HANDLE_INVALID };
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();

        Assert.ThrowsAny<Pkcs11Exception>(() => Session(fake).DecryptVerify(
            Ecdsa(), new ObjectHandle(1), Gcm(), new ObjectHandle(2), input, output, new byte[64], out _));

        Assert.Equal([CKF.CKF_VERIFY], fake.Cancelled);
    }

    /// <summary>
    /// Without <c>C_SessionCancel</c> (any v2.40 module) the abandoned operation may stay active. The
    /// next <c>C_*Init</c> of that kind then fails with <c>CKR_OPERATION_ACTIVE</c>, and must say why.
    /// </summary>
    [Fact]
    public void ModuleThatCannotCancel_NextInitOfThatKind_ExplainsTheActiveOperation()
    {
        var fake = new OperationFake { ProbeReports = NativeCULong.MaxValue, CancelRv = CKR.CKR_FUNCTION_NOT_SUPPORTED, KeepsAbandonedSignActive = true };
        var session = Session(fake);
        Assert.Throws<Pkcs11UnclassifiedException>(() => session.Sign(Ecdsa(), new ObjectHandle(1), "data"u8));

        var e = Assert.Throws<Pkcs11UnclassifiedException>(() => session.Sign(Ecdsa(), new ObjectHandle(1), "data"u8));

        Assert.Equal(CKR.CKR_OPERATION_ACTIVE, e.ReturnValue);
        Assert.Contains("Open a new session", e.Message, StringComparison.Ordinal);
    }

    // A module that ended the operation itself lets the next init through, and nothing lingers.
    [Fact]
    public void ModuleThatCannotCancel_ButEndedTheOperation_NextOperationSucceeds()
    {
        var fake = new OperationFake { ProbeReports = NativeCULong.MaxValue, CancelRv = CKR.CKR_FUNCTION_NOT_SUPPORTED };
        var session = Session(fake);
        Assert.Throws<Pkcs11UnclassifiedException>(() => session.Sign(Ecdsa(), new ObjectHandle(1), "data"u8));

        fake.ProbeReports = null;
        byte[] signature = session.Sign(Ecdsa(), new ObjectHandle(1), "data"u8);

        Assert.Equal(64, signature.Length);
    }

    private static Pkcs11Session Session(OperationFake fake, CapturingLogger? logger = null)
        => new(fake, SessionId, logger is null ? null : new CapturingLoggerFactory(logger));

    private static Mechanism Ecdsa() => new(CKM.CKM_ECDSA_SHA256);
    private static Mechanism Gcm() => new(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], tagBits: 128));

    /// <summary>
    /// Signs and decrypts with fixed-size outputs and records every <c>C_SessionCancel</c>. It can report
    /// a length the library refuses (so the library throws with the operation still active) or fail a
    /// call outright.
    /// </summary>
    private sealed class OperationFake : FakeLowLevelPkcs11Library
    {
        private bool _signActive;

        public NativeCULong? ProbeReports { get; set; }
        public NativeCULong? TooSmallReports { get; init; }
        public int DecryptGrowsBy { get; init; }
        public CKR FillRv { get; init; } = CKR.CKR_OK;
        public CKR CancelRv { get; init; } = CKR.CKR_OK;
        public CKR DecryptInitRv { get; init; } = CKR.CKR_OK;
        public bool KeepsAbandonedSignActive { get; init; }
        public List<ulong> Cancelled { get; } = [];

        public override CKR C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
        {
            if (_signActive)
                return CKR.CKR_OPERATION_ACTIVE;
            _signActive = KeepsAbandonedSignActive;
            return CKR.CKR_OK;
        }

        public override CKR C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        public override CKR C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => DecryptInitRv;

        public override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, out NativeCULong signatureLen)
            => Answer(signature, out signatureLen, 64);

        public override CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, Span<byte> data, out NativeCULong dataLen)
            => Answer(data, out dataLen, encryptedData.Length + DecryptGrowsBy);

        public override CKR C_SessionCancel(NativeCULong session, NativeCULong flags)
        {
            Cancelled.Add((ulong)flags);
            return CancelRv;
        }

        private CKR Answer(Span<byte> output, out NativeCULong length, int produced)
        {
            length = (NativeCULong)(ulong)produced;
            if (output.IsEmpty)
            {
                length = ProbeReports ?? length;
                return CKR.CKR_OK;
            }
            if (FillRv != CKR.CKR_OK)
                return FillRv;
            if (output.Length < produced)
            {
                length = TooSmallReports ?? length;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            output[..produced].Fill(0xA5);
            return CKR.CKR_OK;
        }
    }
}
