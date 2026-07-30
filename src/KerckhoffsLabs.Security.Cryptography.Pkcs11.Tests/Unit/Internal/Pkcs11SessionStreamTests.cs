using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Hermetic coverage for the multi-part (stream) operations of <see cref="Pkcs11Session"/>:
/// the chunked update loop, the CKR_BUFFER_TOO_SMALL retry, the two-call finals with trailing
/// blocks, the verify-tail (OK/SIGNATURE_INVALID/throw) arms, the cancel-on-error unwind path,
/// and VerifyRecover. A backend exercises only the happy path and almost never returns
/// CKR_BUFFER_TOO_SMALL from an update, so these branches are only reachable through the
/// <see cref="ILowLevelPkcs11Library"/> seam.
/// </summary>
public sealed class Pkcs11SessionStreamTests
{
    private const ulong SessionId = 11;

    /// <summary>
    /// Identity-transform fake: each update copies input to output verbatim; the two-call finals
    /// emit <see cref="LastBlock"/>. Flags select the buffer-probe, error and verify outcomes.
    /// </summary>
    private sealed class StreamFake : FakeLowLevelPkcs11Library
    {
        public CKR InitRv = CKR.CKR_OK;
        public CKR UpdateRv = CKR.CKR_OK;
        public bool FirstUpdateBufferTooSmall;
        public byte[] LastBlock = [];
        public byte[] DigestOutput = [0xD0, 0xD1];
        public CKR VerifyFinalRv = CKR.CKR_OK;
        public byte[] RecoveredData = [0xAB, 0xCD, 0xEF];
        public CKR VerifyRecoverRv = CKR.CKR_OK;

        public int UpdateCalls { get; private set; }
        public bool Canceled { get; private set; }
        private bool _retried;

        private CKR Update(byte[] input, NativeCULong inLen, byte[] output, ref NativeCULong outLen)
        {
            UpdateCalls++;
            int n = (int)inLen;
            if (FirstUpdateBufferTooSmall && !_retried)
            {
                _retried = true;
                outLen = (NativeCULong)n;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            Array.Copy(input, output, n);
            outLen = (NativeCULong)n;
            return UpdateRv;
        }

        private CKR Final(byte[]? buffer, ref NativeCULong len)
        {
            if (buffer is null) { len = (NativeCULong)LastBlock.Length; return CKR.CKR_OK; }
            Array.Copy(LastBlock, buffer, LastBlock.Length);
            len = (NativeCULong)LastBlock.Length;
            return CKR.CKR_OK;
        }

        public override CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        public override CKR C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        public override CKR C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism) => InitRv;
        public override CKR C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => InitRv;
        public override CKR C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => InitRv;

        public override CKR C_EncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen)
            => Update(part, partLen, encryptedPart, ref encryptedPartLen);
        public override CKR C_DecryptUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen)
            => Update(encryptedPart, encryptedPartLen, part, ref partLen);
        public override CKR C_EncryptFinal(NativeCULong session, byte[]? lastEncryptedPart, ref NativeCULong lastEncryptedPartLen)
            => Final(lastEncryptedPart, ref lastEncryptedPartLen);
        public override CKR C_DecryptFinal(NativeCULong session, byte[]? lastPart, ref NativeCULong lastPartLen)
            => Final(lastPart, ref lastPartLen);

        public override CKR C_DigestUpdate(NativeCULong session, byte[] part, NativeCULong partLen) { UpdateCalls++; return UpdateRv; }
        public override CKR C_DigestFinal(NativeCULong session, byte[]? digest, ref NativeCULong digestLen)
        {
            if (digest is null) { digestLen = (NativeCULong)DigestOutput.Length; return CKR.CKR_OK; }
            Array.Copy(DigestOutput, digest, DigestOutput.Length);
            digestLen = (NativeCULong)DigestOutput.Length;
            return CKR.CKR_OK;
        }

        public override CKR C_VerifyUpdate(NativeCULong session, byte[] part, NativeCULong partLen) { UpdateCalls++; return UpdateRv; }
        public override CKR C_VerifyFinal(NativeCULong session, byte[] signature, NativeCULong signatureLen) => VerifyFinalRv;

        public override CKR C_VerifyRecover(NativeCULong session, byte[] signature, NativeCULong signatureLen, byte[]? data, ref NativeCULong dataLen)
        {
            if (data is null) { dataLen = (NativeCULong)RecoveredData.Length; return CKR.CKR_OK; }
            Array.Copy(RecoveredData, data, RecoveredData.Length);
            dataLen = (NativeCULong)RecoveredData.Length;
            return VerifyRecoverRv;
        }

        public override CKR C_SessionCancel(NativeCULong session, NativeCULong flags) { Canceled = true; return CKR.CKR_OK; }
    }

    private static Pkcs11Session NewSession(StreamFake fake) => new(fake, SessionId);
    private static Mechanism AesGcm() => new(CKM.CKM_AES_GCM);

    // === Encrypt (stream) ===================================================

    [Fact]
    public void Encrypt_Stream_Ok_WritesTransformedOutput()
    {
        var s = NewSession(new StreamFake());
        var mech = AesGcm();
        using var input = new MemoryStream([1, 2, 3]);
        using var output = new MemoryStream();

        s.Encrypt(mech, new ObjectHandle(1), input, output);

        Assert.Equal(new byte[] { 1, 2, 3 }, output.ToArray());
    }

    [Fact]
    public void Encrypt_Stream_MultiChunk_ProcessesEveryChunk()
    {
        var fake = new StreamFake();
        var s = NewSession(fake);
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
        var s = NewSession(new StreamFake { FirstUpdateBufferTooSmall = true });
        var mech = AesGcm();
        using var input = new MemoryStream([7, 8, 9, 10]);
        using var output = new MemoryStream();

        s.Encrypt(mech, new ObjectHandle(1), input, output);

        Assert.Equal(new byte[] { 7, 8, 9, 10 }, output.ToArray());
    }

    [Fact]
    public void Encrypt_Stream_FinalEmitsTrailingBlock()
    {
        var s = NewSession(new StreamFake { LastBlock = [0xFF] });
        var mech = AesGcm();
        using var input = new MemoryStream([1, 2]);
        using var output = new MemoryStream();

        s.Encrypt(mech, new ObjectHandle(1), input, output);

        Assert.Equal(new byte[] { 1, 2, 0xFF }, output.ToArray());
    }

    [Fact]
    public void Encrypt_Stream_UpdateError_ThrowsAndCancels()
    {
        var fake = new StreamFake { UpdateRv = CKR.CKR_DEVICE_ERROR };
        var s = NewSession(fake);
        var mech = AesGcm();
        using var input = new MemoryStream([1, 2, 3]);
        using var output = new MemoryStream();

        Assert.ThrowsAny<Pkcs11Exception>(() => s.Encrypt(mech, new ObjectHandle(1), input, output));
        Assert.True(fake.Canceled); // unwind cancels the active operation
    }

    [Fact]
    public void Encrypt_Stream_InitError_Throws()
    {
        var s = NewSession(new StreamFake { InitRv = CKR.CKR_KEY_HANDLE_INVALID });
        var mech = AesGcm();
        using var input = new MemoryStream([1]);
        using var output = new MemoryStream();
        Assert.ThrowsAny<Pkcs11Exception>(() => s.Encrypt(mech, new ObjectHandle(1), input, output));
    }

    // === Decrypt (stream) ===================================================

    [Fact]
    public void Decrypt_Stream_Ok_WritesTransformedOutput()
    {
        var s = NewSession(new StreamFake());
        var mech = AesGcm();
        using var input = new MemoryStream([4, 5, 6]);
        using var output = new MemoryStream();

        s.Decrypt(mech, new ObjectHandle(1), input, output);

        Assert.Equal(new byte[] { 4, 5, 6 }, output.ToArray());
    }

    [Fact]
    public void Decrypt_Stream_BufferTooSmall_RetriesAndSucceeds()
    {
        var s = NewSession(new StreamFake { FirstUpdateBufferTooSmall = true });
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
        var s = NewSession(new StreamFake { DigestOutput = [0xAA, 0xBB] });
        var mech = new Mechanism(CKM.CKM_SHA256);
        using var input = new MemoryStream([1, 2, 3]);

        Assert.Equal(new byte[] { 0xAA, 0xBB }, s.Digest(mech, input));
    }

    [Fact]
    public void Digest_Stream_MultiChunk_FeedsEveryChunk()
    {
        var fake = new StreamFake();
        var s = NewSession(fake);
        var mech = new Mechanism(CKM.CKM_SHA256);
        using var input = new MemoryStream([1, 2, 3, 4, 5]);

        s.Digest(mech, input, bufferLength: 2);

        Assert.Equal(3, fake.UpdateCalls);
    }

    [Fact]
    public void Digest_Stream_InitError_Throws()
    {
        var s = NewSession(new StreamFake { InitRv = CKR.CKR_MECHANISM_INVALID });
        var mech = new Mechanism(CKM.CKM_SHA256);
        using var input = new MemoryStream([1]);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.Digest(mech, input));
    }

    // === Verify (stream) ====================================================

    [Fact]
    public void Verify_Stream_Ok_SetsValidTrue()
    {
        var s = NewSession(new StreamFake { VerifyFinalRv = CKR.CKR_OK });
        var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        using var input = new MemoryStream([1, 2, 3]);

        s.Verify(mech, new ObjectHandle(1), input, [9, 9], out bool isValid);

        Assert.True(isValid);
    }

    [Fact]
    public void Verify_Stream_SignatureInvalid_SetsValidFalse()
    {
        var s = NewSession(new StreamFake { VerifyFinalRv = CKR.CKR_SIGNATURE_INVALID });
        var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        using var input = new MemoryStream([1, 2, 3]);

        s.Verify(mech, new ObjectHandle(1), input, [9, 9], out bool isValid);

        Assert.False(isValid);
    }

    [Fact]
    public void Verify_Stream_OtherError_Throws()
    {
        var s = NewSession(new StreamFake { VerifyFinalRv = CKR.CKR_DEVICE_ERROR });
        var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
        using var input = new MemoryStream([1, 2, 3]);

        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.Verify(mech, new ObjectHandle(1), input, [9, 9], out _));
    }

    [Fact]
    public void Verify_Stream_MultiChunk_FeedsEveryChunk()
    {
        var fake = new StreamFake();
        var s = NewSession(fake);
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
        var s = NewSession(new StreamFake { RecoveredData = [1, 2, 3], VerifyRecoverRv = CKR.CKR_OK });
        var mech = new Mechanism(CKM.CKM_RSA_PKCS_PSS);

        byte[] recovered = s.VerifyRecover(mech, new ObjectHandle(1), [9, 9], out bool isValid);

        Assert.True(isValid);
        Assert.Equal(new byte[] { 1, 2, 3 }, recovered);
    }

    [Fact]
    public void VerifyRecover_SignatureInvalid_SetsValidFalse()
    {
        var s = NewSession(new StreamFake { VerifyRecoverRv = CKR.CKR_SIGNATURE_INVALID });
        var mech = new Mechanism(CKM.CKM_RSA_PKCS_PSS);

        s.VerifyRecover(mech, new ObjectHandle(1), [9, 9], out bool isValid);

        Assert.False(isValid);
    }

    [Fact]
    public void VerifyRecover_OtherError_Throws()
    {
        var s = NewSession(new StreamFake { VerifyRecoverRv = CKR.CKR_DEVICE_ERROR });
        var mech = new Mechanism(CKM.CKM_RSA_PKCS_PSS);

        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.VerifyRecover(mech, new ObjectHandle(1), [9, 9], out _));
    }
}
