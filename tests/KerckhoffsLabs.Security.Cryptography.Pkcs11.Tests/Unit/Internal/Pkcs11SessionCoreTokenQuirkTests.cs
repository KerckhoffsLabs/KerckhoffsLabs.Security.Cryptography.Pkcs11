using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// The workarounds <see cref="Pkcs11SessionCore"/> carries for tokens that depart from PKCS#11 v3.2: each is
/// driven through a fake that behaves the way the token does, since the backends the suite runs against
/// either follow the spec or are not always available.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionCoreTokenQuirkTests
{
    private const ulong SessionId = 21;
    private static readonly ObjectHandle Key = new(2);
    private static readonly ObjectHandle WrappingKey = new(3);

    // NSS softoken's classic C_Encrypt ends the operation on CKR_BUFFER_TOO_SMALL, where the spec (§5.2)
    // keeps it active for the retry. Encrypt re-initializes, queries the length and encrypts once.
    [Fact]
    public void Encrypt_WhenTheTokenEndsTheOperationOnBufferTooSmall_ReinitializesAndEncrypts()
    {
        using var fake = new EndsOnBufferTooSmallFake();
        using var session = fake.CreateSession(SessionId);

        byte[] ciphertext = session.Encrypt(new Mechanism(CKM.CKM_AES_GCM), Key, [1, 2, 3]);

        Assert.Equal(EndsOnBufferTooSmallFake.Ciphertext, ciphertext);
        Assert.Equal(2, fake.Inits);
    }

    // NSS softoken never sets the output length for CKM_AES_KEY_WRAP_KWP, so its length probe cannot be
    // trusted. For a secret key the wrapped length follows from CKA_VALUE_LEN (RFC 5649: an 8-byte
    // header, then the key padded to a multiple of 8), so WrapKey sizes the buffer itself and skips it.
    [Fact]
    public void WrapKey_Kwp_OfASecretKey_SizesTheBufferFromItsLength_WithoutAProbe()
    {
        using var fake = new KwpFake(CKO.CKO_SECRET_KEY, valueLen: 20);
        using var session = fake.CreateSession(SessionId);

        byte[] wrapped = session.WrapKey(new Mechanism(CKM.CKM_AES_KEY_WRAP_KWP), WrappingKey, Key);

        Assert.Equal(8 + 24, wrapped.Length);
        Assert.Equal(0, fake.LengthQueries);
    }

    // A private key's wrapped length is not derivable from its attributes, so KWP falls back to the
    // ordinary probe.
    [Fact]
    public void WrapKey_Kwp_OfAPrivateKey_FallsBackToTheLengthProbe()
    {
        using var fake = new KwpFake(CKO.CKO_PRIVATE_KEY, valueLen: 0);
        using var session = fake.CreateSession(SessionId);

        byte[] wrapped = session.WrapKey(new Mechanism(CKM.CKM_AES_KEY_WRAP_KWP), WrappingKey, Key);

        Assert.Equal(KwpFake.ProbedLength, wrapped.Length);
        Assert.Equal(1, fake.LengthQueries);
    }

    // opencryptoki, and Kryoptic before de40e03, answer CKR_BUFFER_TOO_SMALL without writing the length they need:
    // the caller's own stays in place, so a retry at "the reported length" fails the same way. The operation is
    // still active (§5.2), so the single-part calls ask for the length instead.
    [Fact]
    public void Encrypt_WhenTheTokenDoesNotReportTheLength_QueriesItAndEncrypts()
    {
        using var fake = new SilentTooSmallFake(expansion: 40);
        using var session = fake.CreateSession(SessionId);

        byte[] ciphertext = session.Encrypt(new Mechanism(CKM.CKM_AES_GCM), Key, [1, 2, 3]);

        Assert.Equal(SilentTooSmallFake.Transform([1, 2, 3], 40), ciphertext);
        Assert.Equal(1, fake.LengthQueries);
    }

    [Fact]
    public void Decrypt_WhenTheTokenDoesNotReportTheLength_QueriesItAndDecrypts()
    {
        using var fake = new SilentTooSmallFake(expansion: 8);
        using var session = fake.CreateSession(SessionId);

        byte[] plaintext = session.Decrypt(new Mechanism(CKM.CKM_AES_GCM), Key, new byte[16]);

        Assert.Equal(SilentTooSmallFake.Transform(new byte[16], 8), plaintext);
        Assert.Equal(1, fake.LengthQueries);
    }

    // The streaming updates cannot ask for a length without a call shape of their own, so a buffer the token
    // refuses without saying how much it needs is grown instead (opencryptoki's GCM update with an odd buffer).
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void StreamUpdate_WhenTheTokenDoesNotReportTheLength_GrowsTheBuffer(bool encrypt)
    {
        using var fake = new SilentTooSmallFake(expansion: 13);
        using var session = fake.CreateSession(SessionId);
        byte[] input = [.. Enumerable.Range(0, 10).Select(i => (byte)i)];
        using var source = new MemoryStream(input);
        using var sink = new MemoryStream();

        var mechanism = new Mechanism(CKM.CKM_AES_GCM);
        if (encrypt)
            session.Encrypt(mechanism, Key, source, sink, bufferLength: 4);
        else
            session.Decrypt(mechanism, Key, source, sink, bufferLength: 4);

        byte[] expected = [.. SilentTooSmallFake.Transform(input[..4], 13), .. SilentTooSmallFake.Transform(input[4..8], 13), .. SilentTooSmallFake.Transform(input[8..], 13)];
        Assert.Equal(expected, sink.ToArray());
    }

    // A token that refuses every buffer is not grown forever.
    [Fact]
    public void StreamUpdate_WhenTheTokenRefusesEveryBuffer_Throws()
    {
        using var fake = new SilentTooSmallFake(expansion: int.MaxValue / 2);
        using var session = fake.CreateSession(SessionId);
        using var source = new MemoryStream(new byte[4]);
        using var sink = new MemoryStream();

        var e = Assert.ThrowsAny<Pkcs11Exception>(() => session.Encrypt(new Mechanism(CKM.CKM_AES_GCM), Key, source, sink, bufferLength: 4));

        Assert.Equal(CKR.CKR_BUFFER_TOO_SMALL, e.ReturnValue);
    }

    /// <summary>
    /// Produces more ciphertext than the session's first buffer holds and, like NSS, ends the operation when
    /// it reports <c>CKR_BUFFER_TOO_SMALL</c>.
    /// </summary>
    private sealed class EndsOnBufferTooSmallFake : SessionTestModule
    {
        public static readonly byte[] Ciphertext = [.. Enumerable.Range(0, 64).Select(i => (byte)i)];

        private bool _active;

        public int Inits { get; private set; }

        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        {
            Inits++;
            _active = true;
            return CKR.CKR_OK;
        }

        protected override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen)
        {
            encryptedDataLen = (NativeCULong)Ciphertext.Length;
            if (!_active)
                return CKR.CKR_OPERATION_NOT_INITIALIZED;
            if (encryptedData.IsNull)
                return CKR.CKR_OK;
            if (encryptedData.Span.Length < Ciphertext.Length)
            {
                _active = false;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }

            Ciphertext.CopyTo(encryptedData.Span);
            _active = false;
            return CKR.CKR_OK;
        }
    }

    /// <summary>A key of class <c>objectClass</c> and length <c>valueLen</c>, wrapped into whatever buffer it is given.</summary>
    private sealed class KwpFake(CKO objectClass, ulong valueLen) : SessionTestModule
    {
        public const int ProbedLength = 40;

        public int LengthQueries { get; private set; }

        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
        {
            for (int i = 0; i < template.Length; i++)
            {
                var type = (CKA)(ulong)template[i].type;
                using var encoded = new ObjectAttribute(type, type == CKA.CKA_CLASS ? (ulong)objectClass : valueLen);
                byte[] value = encoded.GetValueAsByteArray();
                // Pass 1 (value == NULL): report the size. Pass 2: copy into the caller's buffer.
                if (template[i].value != IntPtr.Zero)
                    UnmanagedMemory.Write(template[i].value, value);
                template[i].valueLen = (NativeCULong)(ulong)value.Length;
            }
            return CKR.CKR_OK;
        }

        protected override CKR C_WrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, NativeBuffer<byte> wrappedKey, ref NativeCULong wrappedKeyLen)
        {
            if (wrappedKey.IsNull)
            {
                LengthQueries++;
                wrappedKeyLen = (NativeCULong)ProbedLength;
                return CKR.CKR_OK;
            }

            wrappedKey.Span.Fill(0x5A);
            wrappedKeyLen = (NativeCULong)(ulong)wrappedKey.Span.Length;
            return CKR.CKR_OK;
        }
    }

    /// <summary>
    /// Emits each input followed by <c>expansion</c> bytes, single-part or per update. Like opencryptoki, it answers
    /// a buffer that is too small with <c>CKR_BUFFER_TOO_SMALL</c> and leaves the length the caller passed in place;
    /// a NULL buffer (a length query) is answered properly.
    /// </summary>
    private sealed class SilentTooSmallFake(int expansion) : SessionTestModule
    {
        public int LengthQueries { get; private set; }

        public static byte[] Transform(ReadOnlySpan<byte> input, int expansion)
            => [.. input, .. Enumerable.Repeat((byte)0xEE, expansion)];

        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;

        protected override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen)
            => Answer(data, encryptedData, ref encryptedDataLen);
        protected override CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, NativeBuffer<byte> data, ref NativeCULong dataLen)
            => Answer(encryptedData, data, ref dataLen);
        protected override CKR C_EncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, NativeBuffer<byte> encryptedPart, ref NativeCULong encryptedPartLen)
            => Answer(part, encryptedPart, ref encryptedPartLen);
        protected override CKR C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen)
            => Answer(encryptedPart, part, ref partLen);
        protected override CKR C_EncryptFinal(NativeCULong session, NativeBuffer<byte> lastEncryptedPart, ref NativeCULong lastEncryptedPartLen)
        {
            lastEncryptedPartLen = (NativeCULong)0UL;
            return CKR.CKR_OK;
        }
        protected override CKR C_DecryptFinal(NativeCULong session, NativeBuffer<byte> lastPart, ref NativeCULong lastPartLen)
        {
            lastPartLen = (NativeCULong)0UL;
            return CKR.CKR_OK;
        }

        private CKR Answer(ReadOnlySpan<byte> input, NativeBuffer<byte> output, ref NativeCULong outputLen)
        {
            long needed = (long)input.Length + expansion;
            if (output.IsNull)
            {
                LengthQueries++;
                outputLen = (NativeCULong)(ulong)needed;
                return CKR.CKR_OK;
            }
            if (output.Span.Length < needed)
                return CKR.CKR_BUFFER_TOO_SMALL; // outputLen left as the caller passed it

            Transform(input, expansion).CopyTo(output.Span);
            outputLen = (NativeCULong)(ulong)needed;
            return CKR.CKR_OK;
        }
    }
}
