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

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.AesCtrParamsAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm takes a bare counter block, not CK_AES_CTR_PARAMS")]
    [MemberData(nameof(MechanismParameterTestCases.AesCtrCounterBitsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(ulong counterBits) => MechanismParameterTestCases.Assert_AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(_backend, counterBits);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.AesCtrParamsAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm takes a bare counter block, not CK_AES_CTR_PARAMS")]
    public void AesCtr_CounterOverflow_IsDataLenRange() => MechanismParameterTestCases.Assert_AesCtr_CounterOverflow_IsDataLenRange(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.MacGeneralLengthsOutOfRange), MemberType = typeof(MechanismParameterTestCases))]
    public void MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(string row)
    {
        if (row.Contains("2^32", StringComparison.Ordinal) && !BouncyHsmBackendFixture.BouncyHsmRefusesAParameterLengthAbove32Bits)
            Assert.Skip("BouncyHsm cuts the MAC length to 32 bits");
        MechanismParameterTestCases.Assert_MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(_backend, row);
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(MechanismParameterTestCases.GenericSecretLengths), MemberType = typeof(MechanismParameterTestCases))]
    public void GenericSecretKeyGen_LengthIsBoundedInBits(string row)
    {
        if (row == "2^32 + 16" && !BouncyHsmBackendFixture.BouncyHsmRefusesAKeyLengthAttributeAbove32Bits)
            Assert.Skip("BouncyHsm cuts CKA_VALUE_LEN to 32 bits");
        if (row == "ulMaxKeySize / 8 + 1" && !BouncyHsmBackendFixture.BouncyHsmBoundsAGenericSecretByItsMaximum)
            Assert.Skip("BouncyHsm makes a generic secret past the ulMaxKeySize it reports");
        MechanismParameterTestCases.Assert_GenericSecretKeyGen_LengthIsBoundedInBits(_backend, row);
    }
}
