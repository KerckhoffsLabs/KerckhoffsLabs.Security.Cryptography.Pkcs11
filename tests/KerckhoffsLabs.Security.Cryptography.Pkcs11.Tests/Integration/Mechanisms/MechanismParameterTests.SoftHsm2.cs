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
}
