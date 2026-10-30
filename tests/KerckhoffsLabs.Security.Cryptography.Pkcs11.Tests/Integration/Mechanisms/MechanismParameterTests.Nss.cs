using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>MechanismParameter over NSS — thin wrapper over <see cref="MechanismParameterTestCases"/>.</summary>
[Collection("Nss")]
public sealed class MechanismParameterTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.AeadParameterFaults), MemberType = typeof(MechanismParameterTestCases))]
    public void AeadParameter_OutOfRange_IsMechanismParamInvalid(string fault)
    {
        if (fault is "GCM pIv NULL" or "GCM pAAD NULL" && !NssBackendFixture.NssSurvivesANullGcmPointer)
            Assert.Skip("NSS copies from a NULL pIv or pAAD and ends the test process");
        if (fault is "GCM ulIvLen 0" or "GCM ulTagBits 136" && !NssBackendFixture.NssRefusesAnOutOfRangeGcmParameterAsInvalid)
            Assert.Skip("NSS refuses ulIvLen 0 and ulTagBits 136 with CKR_HOST_MEMORY");
        if (fault.StartsWith("GCM", StringComparison.Ordinal))
            _backend.RequireClassicAesGcm();
        MechanismParameterTestCases.Assert_AeadParameter_OutOfRange_IsMechanismParamInvalid(_backend, fault);
    }

    [Theory(SkipUnless = nameof(NssBackendFixture.CtrCounterWidthRefusalAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS refuses an AES-CTR counter width out of range with CKR_HOST_MEMORY")]
    [MemberData(nameof(MechanismParameterTestCases.AesCtrCounterBitsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(ulong counterBits) => MechanismParameterTestCases.Assert_AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(_backend, counterBits);

    [Fact(SkipUnless = nameof(NssBackendFixture.CtrBlockCountAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS refuses the last block a 2-bit AES-CTR counter allows")]
    public void AesCtr_CounterOverflow_IsDataLenRange() => MechanismParameterTestCases.Assert_AesCtr_CounterOverflow_IsDataLenRange(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.GeneralLengthMacAvailable), SkipType = typeof(NssBackendFixture), Skip = "NSS refuses every CKM_SHA256_HMAC_GENERAL and CKM_AES_CMAC_GENERAL parameter")]
    [MemberData(nameof(MechanismParameterTestCases.MacGeneralLengthsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(string row) => MechanismParameterTestCases.Assert_MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(_backend, row);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.GenericSecretLengths), MemberType = typeof(MechanismParameterTestCases))]
    public void GenericSecretKeyGen_LengthIsBoundedInBits(string row)
    {
        if (row == "ulMaxKeySize / 8 + 1" && !NssBackendFixture.NssBoundsAGenericSecretByItsMaximum)
            Assert.Skip("NSS makes a generic secret past the ulMaxKeySize it reports");
        MechanismParameterTestCases.Assert_GenericSecretKeyGen_LengthIsBoundedInBits(_backend, row);
    }
}
