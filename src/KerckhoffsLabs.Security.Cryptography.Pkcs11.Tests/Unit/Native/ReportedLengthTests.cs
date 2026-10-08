using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// A length or count the module reports is checked against the buffer it was given. One the module
/// cannot have written, or <c>CK_UNAVAILABLE_INFORMATION</c> as a size, is refused: the result is never
/// padded with zeros the module did not write, and never read past the buffer.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class ReportedLengthTests
{
    private const ulong SessionId = 11;
    private static readonly NativeCULong Unavailable = NativeCULong.MaxValue;

    [Fact]
    public void Sign_FillReportsMoreThanTheBuffer_IsRefused()
    {
        using var fake = new LyingFake { Length = 64, FillReports = (NativeCULong)65UL };

        var e = Assert.Throws<Pkcs11UnclassifiedException>(() => Session(fake).Sign(Ecdsa(), new ObjectHandle(1), "data"u8));

        Assert.Equal("C_Sign", e.Method);
    }

    [Fact]
    public void Sign_ProbeReportsUnavailableInformation_IsRefusedBeforeAllocating()
    {
        using var fake = new LyingFake { ProbeReports = Unavailable };

        Assert.Throws<Pkcs11UnclassifiedException>(() => Session(fake).Sign(Ecdsa(), new ObjectHandle(1), "data"u8));
        Assert.Equal(1, fake.SignCalls);
    }

    [Fact]
    public void Sign_ProbeReportsMoreThanAnArrayCanHold_IsRefused()
    {
        using var fake = new LyingFake { ProbeReports = (NativeCULong)((ulong)Array.MaxLength + 1) };

        Assert.Throws<Pkcs11UnclassifiedException>(() => Session(fake).Sign(Ecdsa(), new ObjectHandle(1), "data"u8));
    }

    /// <summary>
    /// <c>CKR_BUFFER_TOO_SMALL</c> leaves the operation active (PKCS#11 v3.2 §5.2), so a signature
    /// that outgrows the probed size is retried once at the size the module then asks for.
    /// </summary>
    [Fact]
    public void Sign_FillSaysBufferTooSmall_IsRetriedAtTheNewSize()
    {
        using var fake = new LyingFake { Length = 72, ProbeReports = (NativeCULong)70UL };

        byte[] signature = Session(fake).Sign(Ecdsa(), new ObjectHandle(1), "data"u8);

        Assert.Equal(72, signature.Length);
        Assert.Equal(3, fake.SignCalls);
    }

    [Fact]
    public void Sign_FillReportsLessThanTheBuffer_ReturnsWhatWasWritten()
    {
        using var fake = new LyingFake { Length = 64, ProbeReports = (NativeCULong)72UL };

        byte[] signature = Session(fake).Sign(Ecdsa(), new ObjectHandle(1), "data"u8);

        Assert.Equal(64, signature.Length);
    }

    [Fact]
    public void Decrypt_ReportsMoreThanTheBuffer_IsRefused_NotPaddedWithZeros()
    {
        using var fake = new LyingFake { FillReports = (NativeCULong)4096UL };

        var e = Assert.Throws<Pkcs11UnclassifiedException>(() => Session(fake).Decrypt(Gcm(), new ObjectHandle(1), new byte[32]));

        Assert.Equal("C_Decrypt", e.Method);
    }

    [Fact]
    public void Encrypt_ReportsMoreThanTheBuffer_IsRefused()
    {
        using var fake = new LyingFake { FillReports = (NativeCULong)4096UL };

        Assert.Throws<Pkcs11UnclassifiedException>(() => Session(fake).Encrypt(Gcm(), new ObjectHandle(1), new byte[32]));
    }

    [Fact]
    public void FindObjects_ReportsMoreHandlesThanRequested_IsRefused()
    {
        using var fake = new LyingFake { FillReports = (NativeCULong)5UL };
        var session = Session(fake);

        var e = Assert.Throws<Pkcs11UnclassifiedException>(() => session.FindObjects(2));

        Assert.Equal("C_FindObjects", e.Method);
    }

    [Fact]
    public void GetMechanismList_ReportsMoreThanTheBuffer_IsRefused_NotPaddedWithMechanismZero()
    {
        using var fake = new LyingFake { ProbeReports = (NativeCULong)2UL, FillReports = (NativeCULong)3UL };
        var slot = new Pkcs11Slot(fake.LowLevel, 0);

        // Padding used to add CKM 0, CKM_RSA_PKCS_KEY_PAIR_GEN, a mechanism the module never listed.
        Assert.Throws<Pkcs11UnclassifiedException>(() => slot.GetMechanismList());
    }

    [Fact]
    public void GetMechanismList_ProbeReportsUnavailableInformation_IsRefused()
    {
        using var fake = new LyingFake { ProbeReports = Unavailable };

        Assert.Throws<Pkcs11UnclassifiedException>(() => new Pkcs11Slot(fake.LowLevel, 0).GetMechanismList());
    }

    private static Pkcs11Session Session(LyingFake fake) => fake.OpenSession();
    private static Mechanism Ecdsa() => new(CKM.CKM_ECDSA_SHA256);
    private static Mechanism Gcm() => new(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], tagBits: 128));

    /// <summary>
    /// Produces <see cref="Length"/> bytes or items per operation, honestly by default.
    /// <see cref="ProbeReports"/> replaces the length a NULL-buffer call reports, and
    /// <see cref="FillReports"/> the length a call with a buffer reports having written.
    /// </summary>
    private sealed class LyingFake : SessionTestModule
    {
        private readonly List<Pkcs11Session> _sessions = [];

        public int Length { get; init; } = 32;
        public NativeCULong? ProbeReports { get; init; }
        public NativeCULong? FillReports { get; init; }
        public int SignCalls { get; private set; }

        /// <summary>A session on this module, disposed with it.</summary>
        public Pkcs11Session OpenSession()
        {
            Pkcs11Session session = CreateSession(SessionId);
            _sessions.Add(session);
            return session;
        }

        protected override void Disposing()
        {
            foreach (Pkcs11Session session in _sessions)
                session.Dispose();
            base.Disposing();
        }

        protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;

        protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen)
        {
            SignCalls++;
            return Answer(signature, ref signatureLen);
        }

        protected override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen)
            => Answer(encryptedData, ref encryptedDataLen);

        protected override CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, NativeBuffer<byte> data, ref NativeCULong dataLen)
            => Answer(data, ref dataLen);

        protected override CKR C_FindObjects(NativeCULong session, Span<NativeCULong> objects, ref NativeCULong count)
        {
            objects.Fill((NativeCULong)7);
            count = FillReports ?? (NativeCULong)(ulong)objects.Length;
            return CKR.CKR_OK;
        }

        protected override CKR C_GetMechanismList(NativeCULong slotId, NativeBuffer<NativeCULong> mechanismList, ref NativeCULong count)
        {
            if (mechanismList.IsNull)
            {
                count = ProbeReports ?? (NativeCULong)(ulong)Length;
                return CKR.CKR_OK;
            }
            mechanismList.Span.Fill((NativeCULong)(ulong)CKM.CKM_AES_GCM);
            count = FillReports ?? (NativeCULong)(ulong)mechanismList.Span.Length;
            return CKR.CKR_OK;
        }

        private CKR Answer(NativeBuffer<byte> output, ref NativeCULong length)
        {
            if (output.IsNull)
            {
                length = ProbeReports ?? (NativeCULong)(ulong)Length;
                return CKR.CKR_OK;
            }
            if (output.Span.Length < Length)
            {
                length = (NativeCULong)(ulong)Length;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            output.Span[..Length].Fill(0xA5);
            length = FillReports ?? (NativeCULong)(ulong)Length;
            return CKR.CKR_OK;
        }
    }
}
