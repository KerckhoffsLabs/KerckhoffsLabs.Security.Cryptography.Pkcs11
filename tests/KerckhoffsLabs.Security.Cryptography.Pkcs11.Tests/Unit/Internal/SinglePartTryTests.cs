using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// The span-first single-part workers, <c>TryEncrypt</c> and <c>TryDecrypt</c>. They report
/// "too small" only when the real output does not fit; a module that merely asks for a bigger buffer
/// gets one from the scratch pool, and is remembered per slot and mechanism so the next call goes there
/// directly. Whatever happens, the operation is finished and the caller's destination holds nothing but
/// a complete result.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class SinglePartTryTests
{
    private const int TagLength = 16;
    private static readonly byte[] Plaintext = [.. Enumerable.Range(1, 40).Select(i => (byte)i)];
    private static readonly byte[] Ciphertext = [.. Plaintext, .. Enumerable.Repeat((byte)0xEE, TagLength)];

    [Fact]
    public void Decrypt_IntoAnExactDestination_MakesOneCall()
    {
        using var module = new CipherModule();
        using var session = module.CreateSession();
        byte[] destination = new byte[Plaintext.Length];

        Assert.True(session.TryDecrypt(Gcm(), new ObjectHandle(1), Ciphertext, destination, out int written));

        Assert.Equal(Plaintext.Length, written);
        Assert.Equal(Plaintext, destination);
        Assert.Equal(1, module.CallCount("C_Decrypt"));
    }

    // SoftHSM 2.7's AEAD decrypt refuses an output shorter than the ciphertext. The plaintext still fits
    // the caller's destination, so that is success: the first time through scratch at the module's size
    // (two calls), afterwards straight to scratch (one call).
    [Fact]
    public void Decrypt_WhenTheModuleWantsAnInputSizedBuffer_SucceedsAndLearnsIt()
    {
        using var module = new CipherModule { WantsInputSizedOutput = true };
        using var session = module.CreateSession();
        byte[] destination = new byte[Plaintext.Length];

        Assert.True(session.TryDecrypt(Gcm(), new ObjectHandle(1), Ciphertext, destination, out int written));
        Assert.Equal(Plaintext, destination.AsSpan(0, written).ToArray());
        Assert.Equal(2, module.CallCount("C_Decrypt"));

        Array.Clear(destination);
        Assert.True(session.TryDecrypt(Gcm(), new ObjectHandle(1), Ciphertext, destination, out written));
        Assert.Equal(Plaintext, destination.AsSpan(0, written).ToArray());
        Assert.Equal(3, module.CallCount("C_Decrypt"));
    }

    // What is learned is per slot and mechanism: another mechanism, or another slot of the same library
    // (p11-kit fronts several modules behind one), starts again from the spec-compliant assumption.
    [Fact]
    public void LearnedQuirk_IsKeptPerSlotAndMechanism()
    {
        using var module = new CipherModule { WantsInputSizedOutput = true };
        using var slot0 = module.CreateSession();
        using var slot1 = new Pkcs11SessionCore(module.LowLevel, slotId: (NativeCULong)1UL, (ulong)module.OpenSessionCore());
        byte[] destination = new byte[Plaintext.Length];
        slot0.TryDecrypt(Gcm(), new ObjectHandle(1), Ciphertext, destination, out _);
        int calls = module.CallCount("C_Decrypt");

        slot0.TryDecrypt(ChaCha(), new ObjectHandle(1), Ciphertext, destination, out _);
        Assert.Equal(calls + 2, module.CallCount("C_Decrypt"));

        slot1.TryDecrypt(Gcm(), new ObjectHandle(1), Ciphertext, destination, out _);
        Assert.Equal(calls + 4, module.CallCount("C_Decrypt"));
    }

    // A real result longer than the destination is the one "false": the operation is still finished
    // (the next one starts cleanly) and nothing is left in the destination.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Decrypt_WhenThePlaintextDoesNotFit_ReturnsFalse_AndLeavesNothing(bool wantsInputSizedOutput)
    {
        using var module = new CipherModule { WantsInputSizedOutput = wantsInputSizedOutput };
        using var session = module.CreateSession();
        byte[] destination = new byte[Plaintext.Length - 1];

        Assert.False(session.TryDecrypt(Gcm(), new ObjectHandle(1), Ciphertext, destination, out int written));

        Assert.Equal(Plaintext.Length, written);
        Assert.All(destination, b => Assert.Equal(0, b));
        Assert.False(module.DecryptActive);
        Assert.True(session.TryDecrypt(Gcm(), new ObjectHandle(1), Ciphertext, new byte[Plaintext.Length], out _));
    }

    // Once the quirk is known the destination is never handed to the module; a "false" must still
    // leave it cleared, as on the first call.
    [Fact]
    public void Decrypt_WhenTheQuirkIsKnownAndThePlaintextDoesNotFit_ClearsTheDestination()
    {
        using var module = new CipherModule { WantsInputSizedOutput = true };
        using var session = module.CreateSession();
        session.TryDecrypt(Gcm(), new ObjectHandle(1), Ciphertext, new byte[Plaintext.Length], out _);
        byte[] destination = new byte[Plaintext.Length - 1];
        destination.AsSpan().Fill(0xA5);

        Assert.False(session.TryDecrypt(Gcm(), new ObjectHandle(1), Ciphertext, destination, out _));

        Assert.All(destination, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Encrypt_WhenTheCiphertextDoesNotFit_ReturnsFalse_AndFinishesTheOperation()
    {
        using var module = new CipherModule();
        using var session = module.CreateSession();
        byte[] destination = new byte[Plaintext.Length];

        Assert.False(session.TryEncrypt(Gcm(), new ObjectHandle(1), Plaintext, destination, out int written));

        Assert.Equal(Ciphertext.Length, written);
        Assert.All(destination, b => Assert.Equal(0, b));
        Assert.False(module.EncryptActive);
    }

    // NSS ends the operation on CKR_BUFFER_TOO_SMALL, against PKCS#11 v3.2 §5.2: the retry then answers
    // CKR_OPERATION_NOT_INITIALIZED, and the operation is started again, its length queried, run once.
    [Fact]
    public void Decrypt_OnAModuleThatEndsTheOperationOnBufferTooSmall_RestartsIt()
    {
        using var module = new CipherModule { WantsInputSizedOutput = true, EndsOperationOnBufferTooSmall = true };
        using var session = module.CreateSession();
        byte[] destination = new byte[Plaintext.Length];

        Assert.True(session.TryDecrypt(Gcm(), new ObjectHandle(1), Ciphertext, destination, out int written));

        Assert.Equal(Plaintext, destination.AsSpan(0, written).ToArray());
        Assert.Equal(2, module.CallCount("C_DecryptInit"));
    }

    // Whatever a failing module wrote into the destination before failing is not left there.
    [Fact]
    public void Decrypt_ThatFails_ClearsTheDestination()
    {
        using var module = new CipherModule { FailsAfterWriting = true };
        using var session = module.CreateSession();
        byte[] destination = new byte[Plaintext.Length];

        Assert.ThrowsAny<Pkcs11Exception>(() => session.TryDecrypt(Gcm(), new ObjectHandle(1), Ciphertext, destination, out _));

        Assert.All(destination, b => Assert.Equal(0, b));
    }

    // opencryptoki answers CKR_BUFFER_TOO_SMALL without reporting the length, leaving the caller's in
    // place (#185): the length is then asked for, and the result still lands in the destination.
    [Fact]
    public void Decrypt_OnAModuleThatDoesNotReportTheLength_AsksForIt()
    {
        using var module = new CipherModule { WantsInputSizedOutput = true, LeavesLengthUnreported = true };
        using var session = module.CreateSession();
        byte[] destination = new byte[Plaintext.Length];

        Assert.True(session.TryDecrypt(Gcm(), new ObjectHandle(1), Ciphertext, destination, out int written));

        Assert.Equal(Plaintext, destination.AsSpan(0, written).ToArray());
        Assert.Equal(3, module.CallCount("C_Decrypt")); // into the destination, the length, into scratch
    }

    // Both at once: the length is not reported, and asking for it finds the operation ended (NSS's
    // behaviour after CKR_BUFFER_TOO_SMALL), so the operation is started again.
    [Fact]
    public void Decrypt_WhenAskingForTheLengthFindsTheOperationEnded_RestartsIt()
    {
        using var module = new CipherModule { WantsInputSizedOutput = true, LeavesLengthUnreported = true, EndsOperationOnBufferTooSmall = true };
        using var session = module.CreateSession();
        byte[] destination = new byte[Plaintext.Length];

        Assert.True(session.TryDecrypt(Gcm(), new ObjectHandle(1), Ciphertext, destination, out int written));

        Assert.Equal(Plaintext, destination.AsSpan(0, written).ToArray());
        Assert.Equal(2, module.CallCount("C_DecryptInit"));
    }

    [Fact]
    public void Encrypt_OnAModuleThatDoesNotReportTheLength_ReturnsFalseWithTheRealLength()
    {
        using var module = new CipherModule { LeavesLengthUnreported = true };
        using var session = module.CreateSession();
        byte[] destination = new byte[Plaintext.Length];

        Assert.False(session.TryEncrypt(Gcm(), new ObjectHandle(1), Plaintext, destination, out int written));

        Assert.Equal(Ciphertext.Length, written);
        Assert.False(module.EncryptActive);
    }

    // The array-returning Decrypt is built on the same worker and still answers through the quirk.
    [Fact]
    public void ArrayDecrypt_OnAModuleThatWantsAnInputSizedBuffer_ReturnsThePlaintext()
    {
        using var module = new CipherModule { WantsInputSizedOutput = true };
        using var session = module.CreateSession();

        Assert.Equal(Plaintext, session.Decrypt(Gcm(), new ObjectHandle(1), Ciphertext));
        Assert.Equal(1, module.CallCount("C_Decrypt"));
    }

    // Every scratch buffer is zeroized as it goes back: what passes through is often plaintext.
    [Theory]
    [InlineData(64)]
    [InlineData(ScratchBuffer.MaxPooledLength + 1)]
    public void ScratchBuffer_IsZeroizedOnReturn(int length)
    {
        byte[] buffer = ScratchBuffer.Rent(length);
        buffer.AsSpan().Fill(0xA5);

        ScratchBuffer.Return(buffer);

        Assert.True(buffer.AsSpan().IndexOfAnyExcept((byte)0) < 0);
    }

    private static Mechanism Gcm() => new(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], tagBits: 128));

    private static Mechanism ChaCha() => new(CKM.CKM_CHACHA20_POLY1305, new CkmSalsa20ChaCha20Poly1305Params(new byte[12], []));

    /// <summary>
    /// An identity AEAD: the ciphertext is the plaintext followed by a 16-byte tag. It tracks whether an
    /// operation is active as a module does, and can misbehave the ways real modules do.
    /// </summary>
    private sealed class CipherModule : SessionTestModule
    {
        /// <summary>Refuse an output shorter than the ciphertext, asking for the ciphertext's length (SoftHSM 2.7).</summary>
        public bool WantsInputSizedOutput { get; init; }

        /// <summary>End the operation on <c>CKR_BUFFER_TOO_SMALL</c> (NSS).</summary>
        public bool EndsOperationOnBufferTooSmall { get; init; }

        /// <summary>Answer <c>CKR_BUFFER_TOO_SMALL</c> without updating the length (opencryptoki).</summary>
        public bool LeavesLengthUnreported { get; init; }

        /// <summary>Write into the output, then fail with <c>CKR_ENCRYPTED_DATA_INVALID</c>.</summary>
        public bool FailsAfterWriting { get; init; }

        public bool DecryptActive { get; private set; }

        public bool EncryptActive { get; private set; }

        public NativeCULong OpenSessionCore() => NewSessionHandle();

        protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        {
            if (DecryptActive)
                return CKR.CKR_OPERATION_ACTIVE;
            DecryptActive = true;
            return CKR.CKR_OK;
        }

        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        {
            if (EncryptActive)
                return CKR.CKR_OPERATION_ACTIVE;
            EncryptActive = true;
            return CKR.CKR_OK;
        }

        protected override CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, NativeBuffer<byte> data, ref NativeCULong dataLen)
        {
            if (!DecryptActive)
                return CKR.CKR_OPERATION_NOT_INITIALIZED;
            ReadOnlySpan<byte> plaintext = encryptedData[..^TagLength];
            int needed = WantsInputSizedOutput ? encryptedData.Length : plaintext.Length;
            return Answer(plaintext, needed, data, ref dataLen, active => DecryptActive = active);
        }

        protected override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen)
        {
            if (!EncryptActive)
                return CKR.CKR_OPERATION_NOT_INITIALIZED;
            byte[] ciphertext = [.. data, .. Enumerable.Repeat((byte)0xEE, TagLength)];
            return Answer(ciphertext, ciphertext.Length, encryptedData, ref encryptedDataLen, active => EncryptActive = active);
        }

        private CKR Answer(ReadOnlySpan<byte> output, int needed, NativeBuffer<byte> buffer, ref NativeCULong length, Action<bool> setActive)
        {
            if (buffer.IsNull)
            {
                length = (NativeCULong)(ulong)needed;
                return CKR.CKR_OK;
            }
            if (FailsAfterWriting)
            {
                buffer.Span.Fill(0xFF);
                setActive(false);
                return CKR.CKR_ENCRYPTED_DATA_INVALID;
            }
            if (buffer.Span.Length < needed)
            {
                if (!LeavesLengthUnreported)
                    length = (NativeCULong)(ulong)needed;
                if (EndsOperationOnBufferTooSmall)
                    setActive(false);
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            output.CopyTo(buffer.Span);
            length = (NativeCULong)(ulong)output.Length;
            setActive(false);
            return CKR.CKR_OK;
        }
    }
}
