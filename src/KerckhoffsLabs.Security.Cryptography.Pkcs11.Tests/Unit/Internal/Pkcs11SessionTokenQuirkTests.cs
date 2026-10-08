using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// The workarounds <see cref="Pkcs11Session"/> carries for tokens that depart from PKCS#11 v3.2: each is
/// driven through a fake that behaves the way the token does, since the backends the suite runs against
/// either follow the spec or are not always available.
/// </summary>
public sealed class Pkcs11SessionTokenQuirkTests
{
    private const ulong SessionId = 21;
    private static readonly ObjectHandle Key = new(2);
    private static readonly ObjectHandle WrappingKey = new(3);

    // NSS softoken's classic C_Encrypt ends the operation on CKR_BUFFER_TOO_SMALL, where the spec (§5.2)
    // keeps it active for the retry. Encrypt re-initializes, queries the length and encrypts once.
    [Fact]
    public void Encrypt_WhenTheTokenEndsTheOperationOnBufferTooSmall_ReinitializesAndEncrypts()
    {
        var fake = new EndsOnBufferTooSmallFake();
        var session = new Pkcs11Session(fake, SessionId);

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
        var fake = new KwpFake(CKO.CKO_SECRET_KEY, valueLen: 20);
        var session = new Pkcs11Session(fake, SessionId);

        byte[] wrapped = session.WrapKey(new Mechanism(CKM.CKM_AES_KEY_WRAP_KWP), WrappingKey, Key);

        Assert.Equal(8 + 24, wrapped.Length);
        Assert.Equal(0, fake.LengthQueries);
    }

    // A private key's wrapped length is not derivable from its attributes, so KWP falls back to the
    // ordinary probe.
    [Fact]
    public void WrapKey_Kwp_OfAPrivateKey_FallsBackToTheLengthProbe()
    {
        var fake = new KwpFake(CKO.CKO_PRIVATE_KEY, valueLen: 0);
        var session = new Pkcs11Session(fake, SessionId);

        byte[] wrapped = session.WrapKey(new Mechanism(CKM.CKM_AES_KEY_WRAP_KWP), WrappingKey, Key);

        Assert.Equal(KwpFake.ProbedLength, wrapped.Length);
        Assert.Equal(1, fake.LengthQueries);
    }

    /// <summary>
    /// Produces more ciphertext than the session's first buffer holds and, like NSS, ends the operation when
    /// it reports <c>CKR_BUFFER_TOO_SMALL</c>.
    /// </summary>
    private sealed class EndsOnBufferTooSmallFake : FakeLowLevelPkcs11Library
    {
        public static readonly byte[] Ciphertext = [.. Enumerable.Range(0, 64).Select(i => (byte)i)];

        private bool _active;

        public int Inits { get; private set; }

        public override CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
        {
            Inits++;
            _active = true;
            return CKR.CKR_OK;
        }

        public override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> encryptedData, bool lengthOnly, out NativeCULong encryptedDataLen)
        {
            encryptedDataLen = (NativeCULong)Ciphertext.Length;
            if (!_active)
                return CKR.CKR_OPERATION_NOT_INITIALIZED;
            if (lengthOnly)
                return CKR.CKR_OK;
            if (encryptedData.Length < Ciphertext.Length)
            {
                _active = false;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }

            Ciphertext.CopyTo(encryptedData);
            _active = false;
            return CKR.CKR_OK;
        }
    }

    /// <summary>A key of class <c>objectClass</c> and length <c>valueLen</c>, wrapped into whatever buffer it is given.</summary>
    private sealed class KwpFake(CKO objectClass, ulong valueLen) : FakeLowLevelPkcs11Library
    {
        public const int ProbedLength = 40;

        public int LengthQueries { get; private set; }

        public override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
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

        public override CKR C_WrapKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, Span<byte> wrappedKey, bool lengthOnly, out NativeCULong wrappedKeyLen)
        {
            if (lengthOnly)
            {
                LengthQueries++;
                wrappedKeyLen = (NativeCULong)ProbedLength;
                return CKR.CKR_OK;
            }

            wrappedKey.Fill(0x5A);
            wrappedKeyLen = (NativeCULong)(ulong)wrappedKey.Length;
            return CKR.CKR_OK;
        }
    }
}
