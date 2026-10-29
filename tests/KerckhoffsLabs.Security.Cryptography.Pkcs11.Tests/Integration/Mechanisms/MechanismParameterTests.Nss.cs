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
        if (fault.StartsWith("GCM", StringComparison.Ordinal))
            _backend.RequireClassicAesGcm();
        MechanismParameterTestCases.Assert_AeadParameter_OutOfRange_IsMechanismParamInvalid(_backend, fault);
    }

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.AesCtrCounterBitsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(ulong counterBits) => MechanismParameterTestCases.Assert_AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(_backend, counterBits);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void AesCtr_CounterOverflow_IsDataLenRange() => MechanismParameterTestCases.Assert_AesCtr_CounterOverflow_IsDataLenRange(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.MacGeneralLengthsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(string row) => MechanismParameterTestCases.Assert_MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(_backend, row);
}
