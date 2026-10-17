using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
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
    private static readonly Mechanism Oaep =
        new(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256));

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

    // BouncyHsm (harrison314/BouncyHsm#114) answers CKR_BUFFER_TOO_SMALL without setting the length it
    // needs, against PKCS#11 v3.2 §5.2, but keeps the operation active. Encrypt asks with a length query.
    [Fact]
    public void Encrypt_WhenTheTokenLeavesTheLengthUnsetOnBufferTooSmall_QueriesItAndEncrypts()
    {
        using var fake = new LeavesLengthUnsetFake();
        using var session = fake.CreateSession(SessionId);

        byte[] ciphertext = session.Encrypt(Oaep, Key, [1, 2, 3]);

        Assert.Equal(LeavesLengthUnsetFake.Output, ciphertext);
        Assert.Equal(1, fake.Inits);
    }

    // The same token on the decrypt side, for a mechanism whose plaintext is longer than its ciphertext.
    [Fact]
    public void Decrypt_WhenTheTokenLeavesTheLengthUnsetOnBufferTooSmall_QueriesItAndDecrypts()
    {
        using var fake = new LeavesLengthUnsetFake();
        using var session = fake.CreateSession(SessionId);

        byte[] plaintext = session.Decrypt(Oaep, Key, [1, 2, 3]);

        Assert.Equal(LeavesLengthUnsetFake.Output, plaintext);
        Assert.Equal(1, fake.Inits);
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

    /// <summary>
    /// Produces more output than the session's first buffer holds and, like BouncyHsm, reports
    /// <c>CKR_BUFFER_TOO_SMALL</c> without setting the length, while a length query is answered correctly.
    /// The operation stays active throughout, as PKCS#11 v3.2 §5.2 requires.
    /// </summary>
    private sealed class LeavesLengthUnsetFake : SessionTestModule
    {
        public static readonly byte[] Output = [.. Enumerable.Range(0, 64).Select(i => (byte)i)];

        public int Inits { get; private set; }

        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        {
            Inits++;
            return CKR.CKR_OK;
        }

        protected override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen)
            => Produce(encryptedData, ref encryptedDataLen);

        protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        {
            Inits++;
            return CKR.CKR_OK;
        }

        protected override CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, NativeBuffer<byte> data, ref NativeCULong dataLen)
            => Produce(data, ref dataLen);

        private static CKR Produce(NativeBuffer<byte> output, ref NativeCULong outputLen)
        {
            if (output.IsNull)
            {
                outputLen = (NativeCULong)Output.Length;
                return CKR.CKR_OK;
            }
            if (output.Span.Length < Output.Length)
                return CKR.CKR_BUFFER_TOO_SMALL; // the length is left as the caller passed it

            Output.CopyTo(output.Span);
            outputLen = (NativeCULong)Output.Length;
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
}
