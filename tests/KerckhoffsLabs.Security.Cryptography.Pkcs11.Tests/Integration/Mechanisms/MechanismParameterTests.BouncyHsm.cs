using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>MechanismParameter over BouncyHsm — thin wrapper over <see cref="MechanismParameterTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class MechanismParameterTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.AeadParameterFaults), MemberType = typeof(MechanismParameterTestCases))]
    public void AeadParameter_OutOfRange_IsMechanismParamInvalid(string fault)
    {
        if (fault.EndsWith("pAAD NULL", StringComparison.Ordinal))
        {
            if (!BouncyHsmBackendFixture.BouncyHsmRefusesANullAadPointer)
                Assert.Skip("BouncyHsm takes a NULL pAAD behind a length as no AAD");
        }
        else if (!BouncyHsmBackendFixture.BouncyHsmRefusesAnOutOfRangeAeadParameterAsInvalid)
            Assert.Skip("BouncyHsm refuses an out-of-range GCM or CCM parameter with CKR_GENERAL_ERROR");
        MechanismParameterTestCases.Assert_AeadParameter_OutOfRange_IsMechanismParamInvalid(_backend, fault);
    }
}
