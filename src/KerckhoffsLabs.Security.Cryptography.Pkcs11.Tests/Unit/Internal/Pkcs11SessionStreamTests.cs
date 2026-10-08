using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Hermetic coverage for the multi-part (stream) operations of <see cref="Pkcs11Session"/>:
/// the chunked update loop, the CKR_BUFFER_TOO_SMALL retry, the two-call finals with trailing
/// blocks, the verify-tail (OK/SIGNATURE_INVALID/throw) arms, the cancel-on-error unwind path,
/// and VerifyRecover. A backend exercises only the happy path and almost never returns
/// CKR_BUFFER_TOO_SMALL from an update, so these branches are only reachable through a
/// <see cref="FakeModule"/> behind the real loader.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionStreamTests
{
    private const ulong SessionId = 11;

    /// <summary>
    /// Identity-transform fake: each update copies input to output verbatim; the two-call finals
    /// emit <see cref="LastBlock"/>. Flags select the buffer-probe, error and verify outcomes.
    /// </summary>
    private sealed class StreamFake : SessionTestModule
    {
        public CKR InitRv = CKR.CKR_OK;
        public CKR UpdateRv = CKR.CKR_OK;
        public bool FirstUpdateBufferTooSmall;
        public byte[] LastBlock = [];
        public byte[] DigestOutput = [0xD0, 0xD1];
        public CKR VerifyFinalRv = CKR.CKR_OK;
        public byte[] RecoveredData = [0xAB, 0xCD, 0xEF];
        public CKR VerifyRecoverRv = CKR.CKR_OK;
        public CKR DigestKeyRv = CKR.CKR_OK;
        public CKR VerifySignatureInitRv = CKR.CKR_OK;
        public CKR VerifySignatureUpdateRv = CKR.CKR_OK;
        public CKR VerifySignatureFinalRv = CKR.CKR_OK;

        public int UpdateCalls { get; private set; }
        public bool Canceled { get; private set; }
        private bool _retried;

        private CKR Update(ReadOnlySpan<byte> input, NativeBuffer<byte> output, ref NativeCULong outLen)
        {
            UpdateCalls++;
            int n = input.Length;
            if (FirstUpdateBufferTooSmall && !_retried)
            {
                _retried = true;
                outLen = (NativeCULong)n;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            input[..n].CopyTo(output.Span);
            outLen = (NativeCULong)n;
            return UpdateRv;
        }

        private CKR Final(NativeBuffer<byte> buffer, ref NativeCULong len)
        {
            if (buffer.IsNull) { len = (NativeCULong)LastBlock.Length; return CKR.CKR_OK; }
            LastBlock.AsSpan(0, LastBlock.Length).CopyTo(buffer.Span);
            len = (NativeCULong)LastBlock.Length;
            return CKR.CKR_OK;
        }

        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        protected override CKR C_DigestInit(NativeCULong session, CK_MECHANISM mechanism) => InitRv;
        protected override CKR C_VerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        protected override CKR C_VerifyRecoverInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => InitRv;

        protected override CKR C_EncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, NativeBuffer<byte> encryptedPart, ref NativeCULong encryptedPartLen)
            => Update(part, encryptedPart, ref encryptedPartLen);
        protected override CKR C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen)
            => Update(encryptedPart, part, ref partLen);
        protected override CKR C_EncryptFinal(NativeCULong session, NativeBuffer<byte> lastEncryptedPart, ref NativeCULong lastEncryptedPartLen)
            => Final(lastEncryptedPart, ref lastEncryptedPartLen);
        protected override CKR C_DecryptFinal(NativeCULong session, NativeBuffer<byte> lastPart, ref NativeCULong lastPartLen)
            => Final(lastPart, ref lastPartLen);

        protected override CKR C_DigestUpdate(NativeCULong session, ReadOnlySpan<byte> part) { UpdateCalls++; return UpdateRv; }
        protected override CKR C_DigestFinal(NativeCULong session, NativeBuffer<byte> digest, ref NativeCULong digestLen)
        {
            if (digest.IsNull) { digestLen = (NativeCULong)DigestOutput.Length; return CKR.CKR_OK; }
            DigestOutput.AsSpan(0, DigestOutput.Length).CopyTo(digest.Span);
            digestLen = (NativeCULong)DigestOutput.Length;
            return CKR.CKR_OK;
        }

        protected override CKR C_VerifyUpdate(NativeCULong session, ReadOnlySpan<byte> part) { UpdateCalls++; return UpdateRv; }
        protected override CKR C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature) => VerifyFinalRv;

        protected override CKR C_VerifyRecover(NativeCULong session, ReadOnlySpan<byte> signature, NativeBuffer<byte> data, ref NativeCULong dataLen)
        {
            if (data.IsNull) { dataLen = (NativeCULong)RecoveredData.Length; return CKR.CKR_OK; }
            RecoveredData.AsSpan(0, RecoveredData.Length).CopyTo(data.Span);
            dataLen = (NativeCULong)RecoveredData.Length;
            return VerifyRecoverRv;
        }

        protected override CKR C_DigestKey(NativeCULong session, NativeCULong key) => DigestKeyRv;

        protected override CKR C_VerifySignatureInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key, ReadOnlySpan<byte> signature) => VerifySignatureInitRv;
        protected override CKR C_VerifySignatureUpdate(NativeCULong session, ReadOnlySpan<byte> part) { UpdateCalls++; return VerifySignatureUpdateRv; }
        protected override CKR C_VerifySignatureFinal(NativeCULong session) => VerifySignatureFinalRv;

        protected override CKR C_SessionCancel(NativeCULong session, NativeCULong flags) { Canceled = true; return CKR.CKR_OK; }
    }

    private static Mechanism AesGcm() => new(CKM.CKM_AES_GCM);

    // Raw PSS is allowed by the default policy only with explicit parameters.
    private static Mechanism Pss() => new(CKM.CKM_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));

    // === Encrypt (stream) ===================================================

    [Fact]
    public void Encrypt_Stream_Ok_WritesTransformedOutput()
    {
        using var fake = new StreamFake();
        using var s = fake.CreateSession(SessionId);
        var mech = AesGcm();
        using var input = new MemoryStream([1, 2, 3]);
        using var output = new MemoryStream();

        s.Encrypt(mech, new ObjectHandle(1), input, output);

        Assert.Equal(new byte[] { 1, 2, 3 }, output.ToArray());
    }

    [Fact]
    public void Encrypt_Stream_MultiChunk_ProcessesEveryChunk()
    {
        using var fake = new StreamFake();
        using var s = fake.CreateSession(SessionId);
        var mech = AesGcm();
        using var input = new MemoryStream([1, 2, 3, 4, 5]);
        using var output = new MemoryStream();

        s.Encrypt(mech, new ObjectHandle(1), input, output, bufferLength: 2);

        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, output.ToArray());
        Assert.Equal(3, fake.UpdateCalls); // 2 + 2 + 1
    }

    [Fact]
    public void Encrypt_Stream_BufferTooSmall_RetriesAndSucceeds()
    {
        using var fake = new StreamFake { FirstUpdateBufferTooSmall = true };
        using var s = fake.CreateSession(SessionId);
        var mech = AesGcm();
        using var input = new MemoryStream([7, 8, 9, 10]);
        using var output = new MemoryStream();

        s.Encrypt(mech, new ObjectHandle(1), input, output);

        Assert.Equal(new byte[] { 7, 8, 9, 10 }, output.ToArray());
    }

    [Fact]
    public void Encrypt_Stream_FinalEmitsTrailingBlock()
    {
        using var fake = new StreamFake { LastBlock = [0xFF] };
        using var s = fake.CreateSession(SessionId);
        var mech = AesGcm();
        using var input = new MemoryStream([1, 2]);
        using var output = new MemoryStream();

        s.Encrypt(mech, new ObjectHandle(1), input, output);

        Assert.Equal(new byte[] { 1, 2, 0xFF }, output.ToArray());
    }

    [Fact]
    public void Encrypt_Stream_UpdateError_ThrowsAndCancels()
    {
        using var fake = new StreamFake { UpdateRv = CKR.CKR_DEVICE_ERROR };
        using var s = fake.CreateSession(SessionId);
        var mech = AesGcm();
        using var input = new MemoryStream([1, 2, 3]);
        using var output = new MemoryStream();

        Assert.ThrowsAny<Pkcs11Exception>(() => s.Encrypt(mech, new ObjectHandle(1), input, output));
        Assert.True(fake.Canceled); // unwind cancels the active operation
    }

    [Fact]
    public void Encrypt_Stream_InitError_Throws()
    {
        using var fake = new StreamFake { InitRv = CKR.CKR_KEY_HANDLE_INVALID };
        using var s = fake.CreateSession(SessionId);
        var mech = AesGcm();
        using var input = new MemoryStream([1]);
        using var output = new MemoryStream();
        Assert.ThrowsAny<Pkcs11Exception>(() => s.Encrypt(mech, new ObjectHandle(1), input, output));
    }

    // === Decrypt (stream) ===================================================

    [Fact]
    public void Decrypt_Stream_Ok_WritesTransformedOutput()
    {
        using var fake = new StreamFake();
        using var s = fake.CreateSession(SessionId);
        var mech = AesGcm();
        using var input = new MemoryStream([4, 5, 6]);
        using var output = new MemoryStream();

        s.Decrypt(mech, new ObjectHandle(1), input, output);

        Assert.Equal(new byte[] { 4, 5, 6 }, output.ToArray());
    }

    [Fact]
    public void Decrypt_Stream_BufferTooSmall_RetriesAndSucceeds()
    {
        using var fake = new StreamFake { FirstUpdateBufferTooSmall = true };
        using var s = fake.CreateSession(SessionId);
        var mech = AesGcm();
        using var input = new MemoryStream([9, 8, 7]);
        using var output = new MemoryStream();

        s.Decrypt(mech, new ObjectHandle(1), input, output);

        Assert.Equal(new byte[] { 9, 8, 7 }, output.ToArray());
    }

    // === Digest (stream) ====================================================

    [Fact]
    public void Digest_Stream_Ok_ReturnsDigest()
    {
        using var fake = new StreamFake { DigestOutput = [0xAA, 0xBB] };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256);
        using var input = new MemoryStream([1, 2, 3]);

        Assert.Equal(new byte[] { 0xAA, 0xBB }, s.Digest(mech, input));
    }

    [Fact]
    public void Digest_Stream_MultiChunk_FeedsEveryChunk()
    {
        using var fake = new StreamFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256);
        using var input = new MemoryStream([1, 2, 3, 4, 5]);

        s.Digest(mech, input, bufferLength: 2);

        Assert.Equal(3, fake.UpdateCalls);
    }

    [Fact]
    public void Digest_Stream_InitError_Throws()
    {
        using var fake = new StreamFake { InitRv = CKR.CKR_MECHANISM_INVALID };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256);
        using var input = new MemoryStream([1]);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.Digest(mech, input));
    }

    // === Verify (stream) ====================================================

    [Fact]
    public void Verify_Stream_Ok_SetsValidTrue()
    {
        using var fake = new StreamFake { VerifyFinalRv = CKR.CKR_OK };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        using var input = new MemoryStream([1, 2, 3]);

        s.Verify(mech, new ObjectHandle(1), input, [9, 9], out bool isValid);

        Assert.True(isValid);
    }

    [Fact]
    public void Verify_Stream_SignatureInvalid_SetsValidFalse()
    {
        using var fake = new StreamFake { VerifyFinalRv = CKR.CKR_SIGNATURE_INVALID };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        using var input = new MemoryStream([1, 2, 3]);

        s.Verify(mech, new ObjectHandle(1), input, [9, 9], out bool isValid);

        Assert.False(isValid);
    }

    [Fact]
    public void Verify_Stream_OtherError_Throws()
    {
        using var fake = new StreamFake { VerifyFinalRv = CKR.CKR_DEVICE_ERROR };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        using var input = new MemoryStream([1, 2, 3]);

        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.Verify(mech, new ObjectHandle(1), input, [9, 9], out _));
    }

    [Fact]
    public void Verify_Stream_MultiChunk_FeedsEveryChunk()
    {
        using var fake = new StreamFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        using var input = new MemoryStream([1, 2, 3, 4, 5]);

        s.Verify(mech, new ObjectHandle(1), input, [9, 9], out bool isValid, bufferLength: 2);

        Assert.True(isValid);
        Assert.Equal(3, fake.UpdateCalls);
    }

    // === VerifyRecover ======================================================

    [Fact]
    public void VerifyRecover_Ok_ReturnsDataAndValidTrue()
    {
        using var fake = new StreamFake { RecoveredData = [1, 2, 3], VerifyRecoverRv = CKR.CKR_OK };
        using var s = fake.CreateSession(SessionId);
        var mech = Pss();

        byte[] recovered = s.VerifyRecover(mech, new ObjectHandle(1), [9, 9], out bool isValid);

        Assert.True(isValid);
        Assert.Equal(new byte[] { 1, 2, 3 }, recovered);
    }

    [Fact]
    public void VerifyRecover_SignatureInvalid_SetsValidFalse()
    {
        using var fake = new StreamFake { VerifyRecoverRv = CKR.CKR_SIGNATURE_INVALID };
        using var s = fake.CreateSession(SessionId);
        var mech = Pss();

        s.VerifyRecover(mech, new ObjectHandle(1), [9, 9], out bool isValid);

        Assert.False(isValid);
    }

    [Fact]
    public void VerifyRecover_OtherError_Throws()
    {
        using var fake = new StreamFake { VerifyRecoverRv = CKR.CKR_DEVICE_ERROR };
        using var s = fake.CreateSession(SessionId);
        var mech = Pss();

        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.VerifyRecover(mech, new ObjectHandle(1), [9, 9], out _));
    }

    // === DigestKey ===========================================================

    [Fact]
    public void DigestKey_Ok_ReturnsDigest()
    {
        using var fake = new StreamFake { DigestOutput = [0xAA, 0xBB] };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256);

        Assert.Equal(new byte[] { 0xAA, 0xBB }, s.DigestKey(mech, new ObjectHandle(1)));
    }

    // A C_DigestKey error must still leave the digest operation cleanly canceled rather than active
    // on the session, matching every sibling multi-part method's finalized/TryCancelOperation shape.
    [Fact]
    public void DigestKey_Error_ThrowsAndCancels()
    {
        using var fake = new StreamFake { DigestKeyRv = CKR.CKR_KEY_HANDLE_INVALID };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256);

        Assert.ThrowsAny<Pkcs11Exception>(() => s.DigestKey(mech, new ObjectHandle(1)));
        Assert.True(fake.Canceled); // unwind cancels the active operation
    }

    // === VerifySignature (stream) ============================================

    [Fact]
    public void VerifySignature_Stream_Ok_SetsValidTrue()
    {
        using var fake = new StreamFake { VerifySignatureFinalRv = CKR.CKR_OK };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256_RSA_PKCS);
        using var input = new MemoryStream([1, 2, 3]);

        bool verified = s.VerifySignature(mech, new ObjectHandle(1), [9, 9], input);

        Assert.True(verified);
    }

    [Fact]
    public void VerifySignature_Stream_SignatureInvalid_SetsValidFalse()
    {
        using var fake = new StreamFake { VerifySignatureFinalRv = CKR.CKR_SIGNATURE_INVALID };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256_RSA_PKCS);
        using var input = new MemoryStream([1, 2, 3]);

        bool verified = s.VerifySignature(mech, new ObjectHandle(1), [9, 9], input);

        Assert.False(verified);
    }

    [Fact]
    public void VerifySignature_Stream_OtherError_Throws()
    {
        using var fake = new StreamFake { VerifySignatureFinalRv = CKR.CKR_DEVICE_ERROR };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256_RSA_PKCS);
        using var input = new MemoryStream([1, 2, 3]);

        Assert.ThrowsAny<Pkcs11Exception>(() => s.VerifySignature(mech, new ObjectHandle(1), [9, 9], input));
    }

    [Fact]
    public void VerifySignature_Stream_MultiChunk_FeedsEveryChunk()
    {
        using var fake = new StreamFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256_RSA_PKCS);
        using var input = new MemoryStream([1, 2, 3, 4, 5]);

        s.VerifySignature(mech, new ObjectHandle(1), [9, 9], input, bufferLength: 2);

        Assert.Equal(3, fake.UpdateCalls);
    }

    // A C_VerifySignatureUpdate error must still leave the verify-signature operation cleanly
    // canceled rather than active on the session (which would otherwise wedge the next unrelated
    // operation with CKR_OPERATION_ACTIVE), matching every sibling multi-part method.
    [Fact]
    public void VerifySignature_Stream_UpdateError_ThrowsAndCancels()
    {
        using var fake = new StreamFake { VerifySignatureUpdateRv = CKR.CKR_DEVICE_ERROR };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256_RSA_PKCS);
        using var input = new MemoryStream([1, 2, 3]);

        Assert.ThrowsAny<Pkcs11Exception>(() => s.VerifySignature(mech, new ObjectHandle(1), [9, 9], input));
        Assert.True(fake.Canceled); // unwind cancels the active operation
    }
}
