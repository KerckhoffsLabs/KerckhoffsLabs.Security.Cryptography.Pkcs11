using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// A digest or MAC whose length the mechanism fixes is sized up front, without a length query. The size is
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
        using var session = new Pkcs11Session(lowLevel, (ulong)module.OpenSession());

        byte[] digest = session.Digest(new Mechanism(CKM.CKM_SHA256), "data"u8);

        Assert.Equal(20, digest.Length);
        Assert.Equal(1, module.CallCount("C_Digest"));
    }

    [Fact]
    public void Digest_LongerThanTheGuess_IsRetriedAtTheReportedLength()
    {
        using var module = new OutputModule { Produces = 40 };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11Session(lowLevel, (ulong)module.OpenSession());

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
        using var session = new Pkcs11Session(lowLevel, (ulong)module.OpenSession());

        byte[] digest = session.Digest(new Mechanism(CKM.CKM_SHA256), "data"u8);

        Assert.Equal(40, digest.Length);
        Assert.Equal(2, module.CallCount("C_DigestInit"));
    }

    [Fact]
    public void Hmac_FromAModuleThatEndsTheOperationOnBufferTooSmall_IsRestarted()
    {
        using var module = new OutputModule { Produces = 40, EndsOnBufferTooSmall = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var session = new Pkcs11Session(lowLevel, (ulong)module.OpenSession());

        byte[] mac = session.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), new ObjectHandle(1), "data"u8);

        Assert.Equal(40, mac.Length);
        Assert.Equal(2, module.CallCount("C_SignInit"));
    }

    [Theory]
    [InlineData(CKM.CKM_SHA_1, 20)]
    [InlineData(CKM.CKM_SHA384_HMAC, 48)]
    [InlineData(CKM.CKM_SHA3_512, 64)]
    [InlineData(CKM.CKM_AES_CMAC, 16)]
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
    /// the length it needs and, with <see cref="EndsOnBufferTooSmall"/>, also ends the operation.
    /// </summary>
    private sealed class OutputModule : FakeModule
    {
        private bool _active;

        public int Produces { get; init; }
        public bool EndsOnBufferTooSmall { get; init; }

        public NativeCULong OpenSession() => NewSessionHandle();

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
            length = (NativeCULong)(ulong)Produces;
            if (output.IsNull)
                return CKR.CKR_OK;
            if (output.Span.Length < Produces)
            {
                _active = !EndsOnBufferTooSmall;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            output.Span[..Produces].Fill(0x5A);
            _active = false;
            return CKR.CKR_OK;
        }
    }
}
