using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>MechanismParameter over FreeHSM — thin wrapper over <see cref="MechanismParameterTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class MechanismParameterTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.AeadParameterFaults), MemberType = typeof(MechanismParameterTestCases))]
    public void AeadParameter_OutOfRange_IsMechanismParamInvalid(string fault)
    {
        if (fault == "GCM ulTagBits 136" && !FreeHsmBackendFixture.FreeHsmRefusesAnOutOfRangeGcmTagAsInvalid)
            Assert.Skip("FreeHSM refuses ulTagBits 136 with CKR_ARGUMENTS_BAD");
        MechanismParameterTestCases.Assert_AeadParameter_OutOfRange_IsMechanismParamInvalid(_backend, fault);
    }

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.AesCtrCounterBitsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(ulong counterBits) => MechanismParameterTestCases.Assert_AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(_backend, counterBits);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.AesCtrCounterOverflowAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "FreeHSM runs AES-CTR past ulCounterBits, carrying into the nonce")]
    public void AesCtr_CounterOverflow_IsDataLenRange() => MechanismParameterTestCases.Assert_AesCtr_CounterOverflow_IsDataLenRange(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.MacGeneralLengthsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(string row) => MechanismParameterTestCases.Assert_MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(_backend, row);
}
