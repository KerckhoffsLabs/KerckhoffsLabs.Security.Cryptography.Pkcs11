using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// A digest or MAC whose length the mechanism fixes, and an EdDSA signature, is sized up front, without a
/// length query. The size is
/// a guess as far as the module is concerned, so these tests give it modules that disagree: one that writes
/// less, one that needs more and keeps the operation active (PKCS#11 v3.2 §5.2), and one that needs more
/// and ends the operation (as NSS does), which must be restarted.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class KnownLengthOutputTests
{
    [Fact]
    public void Digest_ShorterThanTheGuess_IsTrimmed()
    {
        using var module = new OutputModule { Produces = 20 };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11SessionCore(lowLevel, slotId: default, (ulong)module.OpenSessionCore());

        byte[] digest = session.Digest(new Mechanism(CKM.CKM_SHA256), "data"u8);

        Assert.Equal(20, digest.Length);
        Assert.Equal(1, module.CallCount("C_Digest"));
    }

    [Fact]
    public void Digest_LongerThanTheGuess_IsRetriedAtTheReportedLength()
    {
        using var module = new OutputModule { Produces = 40 };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11SessionCore(lowLevel, slotId: default, (ulong)module.OpenSessionCore());

        byte[] digest = session.Digest(new Mechanism(CKM.CKM_SHA256), "data"u8);

        Assert.Equal(40, digest.Length);
        Assert.Equal(1, module.CallCount("C_DigestInit"));
        Assert.Equal(2, module.CallCount("C_Digest"));
    }

    [Fact]
    public void Digest_FromAModuleThatEndsTheOperationOnBufferTooSmall_IsRestarted()
    {
        using var module = new OutputModule { Produces = 40, EndsOnBufferTooSmall = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11SessionCore(lowLevel, slotId: default, (ulong)module.OpenSessionCore());

        byte[] digest = session.Digest(new Mechanism(CKM.CKM_SHA256), "data"u8);

        Assert.Equal(40, digest.Length);
        Assert.Equal(2, module.CallCount("C_DigestInit"));
    }

    [Fact]
    public void Hmac_FromAModuleThatEndsTheOperationOnBufferTooSmall_IsRestarted()
    {
        using var module = new OutputModule { Produces = 40, EndsOnBufferTooSmall = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11SessionCore(lowLevel, slotId: default, (ulong)module.OpenSessionCore());

        byte[] mac = session.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), new ObjectHandle(1), "data"u8);

        Assert.Equal(40, mac.Length);
        Assert.Equal(2, module.CallCount("C_SignInit"));
    }

    // NSS's softoken: the length query says 144, and only a buffer of exactly 64 bytes signs.
    [Fact]
    public void Ed25519_FromAModuleThatOnlyTakesAnExactBuffer_IsSizedWithoutAQuery()
    {
        using var module = new OutputModule { Produces = 64, Reports = 144, TakesOnlyAnExactBuffer = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11SessionCore(lowLevel, slotId: default, (ulong)module.OpenSessionCore());

        byte[] signature = session.Sign(new Mechanism(CKM.CKM_EDDSA), new ObjectHandle(1), "data"u8);

        Assert.Equal(64, signature.Length);
        Assert.Equal(1, module.CallCount("C_Sign"));
    }

    [Fact]
    public void Ed448_LongerThanTheEd25519Guess_IsRetriedAtTheReportedLength()
    {
        using var module = new OutputModule { Produces = 114 };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11SessionCore(lowLevel, slotId: default, (ulong)module.OpenSessionCore());

        byte[] signature = session.Sign(new Mechanism(CKM.CKM_EDDSA), new ObjectHandle(1), "data"u8);

        Assert.Equal(114, signature.Length);
        Assert.Equal(1, module.CallCount("C_SignInit"));
        Assert.Equal(2, module.CallCount("C_Sign"));
    }

    // opencryptoki's ec_sign: CKR_BUFFER_TOO_SMALL with the length left as the caller passed it.
    [Fact]
    public void Ed448_FromAModuleThatDoesNotReportTheLength_IsQueried()
    {
        using var module = new OutputModule { Produces = 114, LeavesTheLengthOnBufferTooSmall = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11SessionCore(lowLevel, slotId: default, (ulong)module.OpenSessionCore());

        byte[] signature = session.Sign(new Mechanism(CKM.CKM_EDDSA), new ObjectHandle(1), "data"u8);

        Assert.Equal(114, signature.Length);
        Assert.Equal(1, module.CallCount("C_SignInit"));
        Assert.Equal(3, module.CallCount("C_Sign"));
    }

    [Fact]
    public void EdDsa_IsGuessedOnlyWhenSigning()
    {
        Assert.Equal(64, KnownOutputLength.OfSignature(CKM.CKM_EDDSA));
        Assert.Null(KnownOutputLength.Of(CKM.CKM_EDDSA));
        Assert.Equal(32, KnownOutputLength.OfSignature(CKM.CKM_SHA256_HMAC));
        Assert.Null(KnownOutputLength.OfSignature(CKM.CKM_ECDSA_SHA256));
    }

    [Theory]
    [InlineData(CKM.CKM_MD5, 16)]
    [InlineData(CKM.CKM_MD5_HMAC, 16)]
    [InlineData(CKM.CKM_AES_CMAC, 16)]
    [InlineData(CKM.CKM_SHA_1, 20)]
    [InlineData(CKM.CKM_SHA_1_HMAC, 20)]
    [InlineData(CKM.CKM_RIPEMD160, 20)]
    [InlineData(CKM.CKM_RIPEMD160_HMAC, 20)]
    [InlineData(CKM.CKM_BLAKE2B_160, 20)]
    [InlineData(CKM.CKM_BLAKE2B_160_HMAC, 20)]
    [InlineData(CKM.CKM_SHA224, 28)]
    [InlineData(CKM.CKM_SHA224_HMAC, 28)]
    [InlineData(CKM.CKM_SHA512_224, 28)]
    [InlineData(CKM.CKM_SHA512_224_HMAC, 28)]
    [InlineData(CKM.CKM_SHA3_224, 28)]
    [InlineData(CKM.CKM_SHA3_224_HMAC, 28)]
    [InlineData(CKM.CKM_SHA256, 32)]
    [InlineData(CKM.CKM_SHA256_HMAC, 32)]
    [InlineData(CKM.CKM_SHA512_256, 32)]
    [InlineData(CKM.CKM_SHA512_256_HMAC, 32)]
    [InlineData(CKM.CKM_SHA3_256, 32)]
    [InlineData(CKM.CKM_SHA3_256_HMAC, 32)]
    [InlineData(CKM.CKM_BLAKE2B_256, 32)]
    [InlineData(CKM.CKM_BLAKE2B_256_HMAC, 32)]
    [InlineData(CKM.CKM_SHA384, 48)]
    [InlineData(CKM.CKM_SHA384_HMAC, 48)]
    [InlineData(CKM.CKM_SHA3_384, 48)]
    [InlineData(CKM.CKM_SHA3_384_HMAC, 48)]
    [InlineData(CKM.CKM_BLAKE2B_384, 48)]
    [InlineData(CKM.CKM_BLAKE2B_384_HMAC, 48)]
    [InlineData(CKM.CKM_SHA512, 64)]
    [InlineData(CKM.CKM_SHA512_HMAC, 64)]
    [InlineData(CKM.CKM_SHA3_512, 64)]
    [InlineData(CKM.CKM_SHA3_512_HMAC, 64)]
    [InlineData(CKM.CKM_BLAKE2B_512, 64)]
    [InlineData(CKM.CKM_BLAKE2B_512_HMAC, 64)]
    [InlineData(CKM.CKM_DES3_CMAC, 8)]
    public void KnownLengths_MatchTheMechanism(CKM mechanism, int length)
        => Assert.Equal(length, KnownOutputLength.Of(mechanism));

    // The length depends on the key, or on the mechanism's parameter.
    [Theory]
    [InlineData(CKM.CKM_ECDSA_SHA256)]
    [InlineData(CKM.CKM_SHA256_RSA_PKCS_PSS)]
    [InlineData(CKM.CKM_SHA256_HMAC_GENERAL)]
    public void LengthsThatAreNotFixed_AreNotGuessed(CKM mechanism)
        => Assert.Null(KnownOutputLength.Of(mechanism));

    /// <summary>
    /// Digests and signs to <see cref="Produces"/> bytes. Asked to fill a buffer that is too small, it reports
    /// the length it needs and, with <see cref="EndsOnBufferTooSmall"/>, also ends the operation. With
    /// <see cref="TakesOnlyAnExactBuffer"/> it refuses any other buffer size, as NSS does for EdDSA, and with
    /// <see cref="LeavesTheLengthOnBufferTooSmall"/> it does not report the length it needs, as opencryptoki
    /// does for EC signatures.
    /// </summary>
    private sealed class OutputModule : FakeModule
    {
        private bool _active;

        public int Produces { get; init; }
        public bool EndsOnBufferTooSmall { get; init; }

        /// <summary>The length the query reports, when it is not <see cref="Produces"/>.</summary>
        public int? Reports { get; init; }

        public bool TakesOnlyAnExactBuffer { get; init; }

        public bool LeavesTheLengthOnBufferTooSmall { get; init; }

        public NativeCULong OpenSessionCore() => NewSessionHandle();

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;
        protected override CKR C_DigestInit(NativeCULong session, CK_MECHANISM mechanism) => Begin();
        protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => Begin();

        protected override CKR C_Digest(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> digest, ref NativeCULong digestLen)
            => Output(digest, ref digestLen);

        protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen)
            => Output(signature, ref signatureLen);

        private CKR Begin()
        {
            _active = true;
            return CKR.CKR_OK;
        }

        private CKR Output(NativeBuffer<byte> output, ref NativeCULong length)
        {
            if (!_active)
                return CKR.CKR_OPERATION_NOT_INITIALIZED;
            length = (NativeCULong)(ulong)(Reports ?? Produces);
            if (output.IsNull)
                return CKR.CKR_OK;
            if (TakesOnlyAnExactBuffer && output.Span.Length != Produces)
            {
                _active = false;
                return CKR.CKR_ARGUMENTS_BAD;
            }
            length = (NativeCULong)(ulong)Produces;
            if (output.Span.Length < Produces)
            {
                if (LeavesTheLengthOnBufferTooSmall)
                    length = (NativeCULong)(ulong)output.Span.Length;
                _active = !EndsOnBufferTooSmall;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            output.Span[..Produces].Fill(0x5A);
            _active = false;
            return CKR.CKR_OK;
        }
    }
}
