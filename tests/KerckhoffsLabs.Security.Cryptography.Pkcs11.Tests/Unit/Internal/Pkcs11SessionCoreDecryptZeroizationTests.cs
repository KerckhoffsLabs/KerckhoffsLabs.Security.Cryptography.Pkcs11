using System.Runtime;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// A token can write into a decryption's output buffer and then fail: part of the plaintext, or plaintext
/// whose tag or integrity check failed afterwards. Whichever call fails, the buffer the session handed it
/// must be zeroized before the exception leaves the session. The fake records the address and length of
/// every output buffer it writes into; once the call has thrown those arrays are unreachable, so the GC is
/// held off until they are read back, and they are still where the token wrote.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionCoreDecryptZeroizationTests
{
    private const ulong SessionId = 23;
    private const byte Plaintext = 0xC5;

    /// <summary>
    /// How much a test may allocate while the GC is held off: plenty for a few small buffers and an
    /// exception, and within what a 32-bit process accepts (its ephemeral budget is far smaller than a
    /// 64-bit one's, and a larger request throws <see cref="ArgumentOutOfRangeException"/>).
    /// </summary>
    private const long NoGcBudget = 1024 * 1024;

    private static readonly ObjectHandle Key = new(2);
    private static readonly ObjectHandle VerificationKey = new(3);

    [Fact]
    public void Decrypt_WhenTheTokenFailsAfterWriting_ZeroizesTheBuffer()
    {
        AssertZeroizedAfterFailure(
            () => new WritesThenFailsFake((CKR.CKR_ENCRYPTED_DATA_INVALID, 0)),
            s => s.Decrypt(new Mechanism(CKM.CKM_AES_GCM), Key, new byte[32]),
            CKR.CKR_ENCRYPTED_DATA_INVALID,
            buffers: 1);
    }

    [Fact]
    public void Decrypt_WhenTheTokenFailsOnTheResizedBuffer_ZeroizesBoth()
    {
        AssertZeroizedAfterFailure(
            () => new WritesThenFailsFake((CKR.CKR_BUFFER_TOO_SMALL, 16), (CKR.CKR_ENCRYPTED_DATA_INVALID, 0)),
            s => s.Decrypt(new Mechanism(CKM.CKM_AES_GCM), Key, new byte[32]),
            CKR.CKR_ENCRYPTED_DATA_INVALID,
            buffers: 2);
    }

    // CKR_BUFFER_TOO_SMALL without a usable length is answered with a length query; when that fails, the
    // first buffer is still the one the token wrote into.
    [Fact]
    public void Decrypt_WhenTheLengthQueryFails_ZeroizesTheFirstBuffer()
    {
        AssertZeroizedAfterFailure(
            () => new WritesThenFailsFake((CKR.CKR_BUFFER_TOO_SMALL, 0)) { QueryRv = CKR.CKR_DEVICE_ERROR },
            s => s.Decrypt(new Mechanism(CKM.CKM_AES_GCM), Key, new byte[32]),
            CKR.CKR_DEVICE_ERROR,
            buffers: 1);
    }

    // A length the token cannot have written is refused, and so is what it wrote.
    [Fact]
    public void Decrypt_WhenTheTokenMisreportsTheLength_ZeroizesTheBuffer()
    {
        AssertZeroizedAfterFailure(
            () => new WritesThenFailsFake((CKR.CKR_OK, 1)),
            s => s.Decrypt(new Mechanism(CKM.CKM_AES_GCM), Key, new byte[32]),
            expected: null,
            buffers: 1);
    }

    [Fact]
    public void Decrypt_Stream_WhenTheFinalFails_ZeroizesTheLastPart()
    {
        AssertZeroizedAfterFailure(
            () => new WritesThenFailsFake((CKR.CKR_ENCRYPTED_DATA_INVALID, 0)),
            s =>
            {
                using var input = new MemoryStream(new byte[8]);
                using var output = new MemoryStream();
                s.Decrypt(new Mechanism(CKM.CKM_AES_GCM), Key, input, output, bufferLength: 4);
            },
            CKR.CKR_ENCRYPTED_DATA_INVALID,
            buffers: 1);
    }

    [Fact]
    public void DecryptDigest_Stream_WhenTheFinalFails_ZeroizesTheLastPart()
    {
        AssertZeroizedAfterFailure(
            () => new WritesThenFailsFake((CKR.CKR_ENCRYPTED_DATA_INVALID, 0)),
            s =>
            {
                using var input = new MemoryStream(new byte[8]);
                using var output = new MemoryStream();
                s.DecryptDigest(new Mechanism(CKM.CKM_SHA256), new Mechanism(CKM.CKM_AES_GCM), Key, input, output, bufferLength: 4);
            },
            CKR.CKR_ENCRYPTED_DATA_INVALID,
            buffers: 1);
    }

    [Fact]
    public void DecryptDigest_Stream_WhenTheFinalFailsOnTheResizedBuffer_ZeroizesBoth()
    {
        AssertZeroizedAfterFailure(
            () => new WritesThenFailsFake((CKR.CKR_BUFFER_TOO_SMALL, 16), (CKR.CKR_ENCRYPTED_DATA_INVALID, 0)),
            s =>
            {
                using var input = new MemoryStream(new byte[8]);
                using var output = new MemoryStream();
                s.DecryptDigest(new Mechanism(CKM.CKM_SHA256), new Mechanism(CKM.CKM_AES_GCM), Key, input, output, bufferLength: 4);
            },
            CKR.CKR_ENCRYPTED_DATA_INVALID,
            buffers: 2);
    }

    [Fact]
    public void DecryptVerify_Stream_WhenTheFinalFails_ZeroizesTheLastPart()
    {
        AssertZeroizedAfterFailure(
            () => new WritesThenFailsFake((CKR.CKR_ENCRYPTED_DATA_INVALID, 0)),
            s =>
            {
                using var input = new MemoryStream(new byte[8]);
                using var output = new MemoryStream();
                s.DecryptVerify(new Mechanism(CKM.CKM_SHA256_HMAC), VerificationKey, new Mechanism(CKM.CKM_AES_GCM), Key,
                    input, output, signature: [9, 9], bufferLength: 4);
            },
            CKR.CKR_ENCRYPTED_DATA_INVALID,
            buffers: 1);
    }

    // GCM's message output is as long as its input, so it is filled in one call into a buffer of that size.
    [Fact]
    public void MessageDecrypt_WhenTheTagCheckFailsAfterWriting_ZeroizesTheBuffer()
    {
        AssertZeroizedAfterFailure(
            () => new WritesThenFailsFake((CKR.CKR_AEAD_DECRYPT_FAILED, 0)),
            s => s.MessageDecrypt(new Mechanism(CKM.CKM_AES_GCM), Key, CkmGcmMessageParams.ForDecrypt(new byte[12], new byte[16]), [0xAD], new byte[32]),
            CKR.CKR_AEAD_DECRYPT_FAILED,
            buffers: 1);
    }

    [Fact]
    public void MessageDecrypt_WhenTheTagCheckFailsOnTheResizedBuffer_ZeroizesBoth()
    {
        AssertZeroizedAfterFailure(
            () => new WritesThenFailsFake((CKR.CKR_BUFFER_TOO_SMALL, 16), (CKR.CKR_AEAD_DECRYPT_FAILED, 0)),
            s => s.MessageDecrypt(new Mechanism(CKM.CKM_AES_GCM), Key, CkmGcmMessageParams.ForDecrypt(new byte[12], new byte[16]), [0xAD], new byte[32]),
            CKR.CKR_AEAD_DECRYPT_FAILED,
            buffers: 2);
    }

    /// <summary>
    /// Runs <paramref name="call"/> against a fresh fake, expects it to fail with <paramref name="expected"/>
    /// (any <see cref="Pkcs11Exception"/> when <see langword="null"/>), and checks that each of the
    /// <paramref name="buffers"/> output buffers the fake wrote into reads back as zeros. An attempt during
    /// which a collection ran anyway is repeated, since the buffers may then have moved.
    /// </summary>
    private static unsafe void AssertZeroizedAfterFailure(
        Func<WritesThenFailsFake> newFake, Action<Pkcs11SessionCore> call, CKR? expected, int buffers)
    {
        for (int attempt = 0; attempt < 5; attempt++)
        {
            using WritesThenFailsFake fake = newFake();
            using Pkcs11SessionCore session = fake.CreateSession(SessionId);

            Assert.True(GC.TryStartNoGCRegion(NoGcBudget));
            Pkcs11Exception? error = null;
            var contents = new List<byte[]>();
            bool collected;
            try
            {
                try
                {
                    call(session);
                }
                catch (Pkcs11Exception e)
                {
                    error = e;
                }
                foreach ((IntPtr address, int length) in fake.Written)
                    contents.Add(new ReadOnlySpan<byte>((void*)address, length).ToArray());
            }
            finally
            {
                // Any other exception propagates; the region must not outlive the attempt either way.
                collected = GCSettings.LatencyMode != GCLatencyMode.NoGCRegion;
                if (!collected)
                    GC.EndNoGCRegion();
            }
            if (collected)
                continue;

            Pkcs11Exception failure = Assert.IsType<Pkcs11Exception>(error, exactMatch: false);
            if (expected is CKR rv)
                Assert.Equal(rv, failure.ReturnValue);
            Assert.Equal(buffers, contents.Count);
            Assert.All(contents, written => Assert.Equal(new byte[written.Length], written));
            return;
        }
        Assert.Fail("A collection ran during every attempt.");
    }

    /// <summary>
    /// Writes <see cref="Plaintext"/> over every decryption output buffer it is given, then answers with the
    /// next of its <c>fills</c>: the return value, and how far past the buffer's capacity the reported length
    /// lies (0 leaves the length at the capacity, which reports nothing). A length query reports 16 bytes,
    /// or fails with <see cref="QueryRv"/>. Updates are an identity transform.
    /// </summary>
    private sealed class WritesThenFailsFake(params (CKR Rv, int Excess)[] fills) : SessionTestModule
    {
        private readonly Queue<(CKR Rv, int Excess)> _fills = new(fills);
        private readonly List<(IntPtr Address, int Length)> _written = [];

        public CKR QueryRv { get; init; } = CKR.CKR_OK;

        public IReadOnlyList<(IntPtr Address, int Length)> Written => _written;

        protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_DigestInit(NativeCULong session, CK_MECHANISM mechanism) => CKR.CKR_OK;
        protected override CKR C_VerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_MessageDecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_MessageDecryptFinal(NativeCULong session) => CKR.CKR_OK;
        protected override CKR C_SessionCancel(NativeCULong session, NativeCULong flags) => CKR.CKR_OK;

        protected override CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, NativeBuffer<byte> data, ref NativeCULong dataLen)
            => Fill(data, ref dataLen);
        protected override CKR C_DecryptFinal(NativeCULong session, NativeBuffer<byte> lastPart, ref NativeCULong lastPartLen)
            => Fill(lastPart, ref lastPartLen);
        protected override CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext, NativeBuffer<byte> plaintext, ref NativeCULong plaintextLen)
            => Fill(plaintext, ref plaintextLen);

        protected override CKR C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen)
            => Identity(encryptedPart, part, ref partLen);
        protected override CKR C_DecryptDigestUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen)
            => Identity(encryptedPart, part, ref partLen);
        protected override CKR C_DecryptVerifyUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen)
            => Identity(encryptedPart, part, ref partLen);

        private unsafe CKR Fill(NativeBuffer<byte> output, ref NativeCULong length)
        {
            if (output.IsNull)
            {
                length = (NativeCULong)16UL;
                return QueryRv;
            }

            output.Span.Fill(Plaintext);
            fixed (byte* p = output.Span)
                _written.Add(((IntPtr)p, output.Span.Length));

            (CKR rv, int excess) = _fills.Dequeue();
            length = (NativeCULong)(ulong)(output.Span.Length + excess);
            return rv;
        }

        private static CKR Identity(ReadOnlySpan<byte> input, NativeBuffer<byte> output, ref NativeCULong length)
        {
            input.CopyTo(output.Span);
            length = (NativeCULong)(ulong)input.Length;
            return CKR.CKR_OK;
        }
    }
}
