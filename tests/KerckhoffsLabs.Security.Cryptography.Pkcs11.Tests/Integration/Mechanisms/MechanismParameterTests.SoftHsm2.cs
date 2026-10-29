using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>MechanismParameter over SoftHSM2 — thin wrapper over <see cref="MechanismParameterTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class MechanismParameterTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.AeadParameterFaults), MemberType = typeof(MechanismParameterTestCases))]
    public void AeadParameter_OutOfRange_IsMechanismParamInvalid(string fault)
    {
        if (fault is "GCM pIv NULL" or "GCM pAAD NULL" && !SoftHsmBackendFixture.SoftHsmSurvivesANullGcmPointer)
            Assert.Skip("SoftHSM2 copies from a NULL pIv or pAAD and ends the test process");
        if (fault is "GCM ulIvLen 0" or "GCM ulTagBits 136" && !SoftHsmBackendFixture.SoftHsmRefusesAnOutOfRangeGcmParameterAsInvalid)
            Assert.Skip("SoftHSM2 takes ulIvLen 0 and refuses ulTagBits 136 with CKR_ARGUMENTS_BAD");
        MechanismParameterTestCases.Assert_AeadParameter_OutOfRange_IsMechanismParamInvalid(_backend, fault);
    }

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.AesCtrCounterBitsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(ulong counterBits) => MechanismParameterTestCases.Assert_AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(_backend, counterBits);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void AesCtr_CounterOverflow_IsDataLenRange() => MechanismParameterTestCases.Assert_AesCtr_CounterOverflow_IsDataLenRange(_backend);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.MacGeneralLengthsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(string row) => MechanismParameterTestCases.Assert_MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(_backend, row);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.GenericSecretLengths), MemberType = typeof(MechanismParameterTestCases))]
    public void GenericSecretKeyGen_LengthIsBoundedInBits(string row)
    {
        if (row == "ulMaxKeySize / 8 + 1" && !SoftHsmBackendFixture.SoftHsmBoundsAGenericSecretByItsMaximum)
            Assert.Skip("SoftHSM2 makes a generic secret past the ulMaxKeySize it reports");
        MechanismParameterTestCases.Assert_GenericSecretKeyGen_LengthIsBoundedInBits(_backend, row);
    }
}
