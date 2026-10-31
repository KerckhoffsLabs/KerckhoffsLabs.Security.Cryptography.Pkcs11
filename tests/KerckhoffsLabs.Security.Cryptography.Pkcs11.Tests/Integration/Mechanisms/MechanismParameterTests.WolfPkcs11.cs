using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>MechanismParameter over wolfPKCS11 — thin wrapper over <see cref="MechanismParameterTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class MechanismParameterTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(MechanismParameterTestCases.AeadParameterFaults), MemberType = typeof(MechanismParameterTestCases))]
    public void AeadParameter_OutOfRange_IsMechanismParamInvalid(string fault) => MechanismParameterTestCases.Assert_AeadParameter_OutOfRange_IsMechanismParamInvalid(_backend, fault);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(MechanismParameterTestCases.AesCtrCounterBitsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(ulong counterBits) => MechanismParameterTestCases.Assert_AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(_backend, counterBits);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void AesCtr_CounterOverflow_IsDataLenRange() => MechanismParameterTestCases.Assert_AesCtr_CounterOverflow_IsDataLenRange(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(MechanismParameterTestCases.MacGeneralLengthsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(string row) => MechanismParameterTestCases.Assert_MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(_backend, row);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(MechanismParameterTestCases.GenericSecretLengths), MemberType = typeof(MechanismParameterTestCases))]
    public void GenericSecretKeyGen_LengthIsBoundedInBits(string row)
    {
        if (row is "ulMaxKeySize / 8 + 1" or "2^32 + 16" && !WolfPkcs11BackendFixture.WolfPkcs11RefusesAGenericSecretLengthAsInvalid)
            Assert.Skip("wolfPKCS11 refuses a generic secret past its maximum with CKR_FUNCTION_FAILED");
        MechanismParameterTestCases.Assert_GenericSecretKeyGen_LengthIsBoundedInBits(_backend, row);
    }
}
