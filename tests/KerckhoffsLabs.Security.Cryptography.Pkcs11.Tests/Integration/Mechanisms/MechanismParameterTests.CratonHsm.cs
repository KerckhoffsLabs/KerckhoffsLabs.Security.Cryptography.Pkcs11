using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>MechanismParameter over Craton HSM — thin wrapper over <see cref="MechanismParameterTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class MechanismParameterTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.AeadParameterFaults), MemberType = typeof(MechanismParameterTestCases))]
    public void AeadParameter_OutOfRange_IsMechanismParamInvalid(string fault) => MechanismParameterTestCases.Assert_AeadParameter_OutOfRange_IsMechanismParamInvalid(_backend, fault);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.AesCtrParamsAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Craton HSM takes a bare counter block, not CK_AES_CTR_PARAMS")]
    [MemberData(nameof(MechanismParameterTestCases.AesCtrCounterBitsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(ulong counterBits) => MechanismParameterTestCases.Assert_AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(_backend, counterBits);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.AesCtrParamsAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Craton HSM takes a bare counter block, not CK_AES_CTR_PARAMS")]
    public void AesCtr_CounterOverflow_IsDataLenRange() => MechanismParameterTestCases.Assert_AesCtr_CounterOverflow_IsDataLenRange(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.MacGeneralLengthsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(string row) => MechanismParameterTestCases.Assert_MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(_backend, row);
}
