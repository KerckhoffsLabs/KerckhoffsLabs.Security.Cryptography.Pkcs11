using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>MechanismCoverage over NSS — thin wrapper over <see cref="MechanismCoverageTestCases"/>.</summary>
[Collection("Nss")]
public sealed class MechanismCoverageTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.DigestVectors), MemberType = typeof(MechanismCoverageTestCases))]
    public void Digest_KnownAnswer(CKM mechanism, string message, string expected) => MechanismCoverageTestCases.Assert_Digest_KnownAnswer(_backend, mechanism, message, expected);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Gost3411_WithTheDefaultParameterSet_DigestsAsWithout() => MechanismCoverageTestCases.Assert_Gost3411_WithTheDefaultParameterSet_DigestsAsWithout(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.Sha512TVectors), MemberType = typeof(MechanismCoverageTestCases))]
    public void Sha512T_IsSha512TruncatedToT(int t, string expected) => MechanismCoverageTestCases.Assert_Sha512T_IsSha512TruncatedToT(_backend, t, expected);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.HmacFamilies), MemberType = typeof(MechanismCoverageTestCases))]
    public void Hmac_IsRfc2104OverTheHash(string family) => MechanismCoverageTestCases.Assert_Hmac_IsRfc2104OverTheHash(_backend, family);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.HmacGeneralFamilies), MemberType = typeof(MechanismCoverageTestCases))]
    public void HmacGeneral_IsTheLeadingBytesOfTheHmac(string family) => MechanismCoverageTestCases.Assert_HmacGeneral_IsTheLeadingBytesOfTheHmac(_backend, family);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.KeyDerivationFamilies), MemberType = typeof(MechanismCoverageTestCases))]
    public void DigestKeyDerivation_IsTheDigestOfTheBaseKey(string family) => MechanismCoverageTestCases.Assert_DigestKeyDerivation_IsTheDigestOfTheBaseKey(_backend, family);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.ShakeDerivations), MemberType = typeof(MechanismCoverageTestCases))]
    public void ShakeKeyDerivation_IsTheXofOfTheBaseKey(CKM mechanism, int length) => MechanismCoverageTestCases.Assert_ShakeKeyDerivation_IsTheXofOfTheBaseKey(_backend, mechanism, length);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [InlineData(CKM.CKM_AES_ECB_ENCRYPT_DATA)]
    [InlineData(CKM.CKM_AES_CBC_ENCRYPT_DATA)]
    public void AesEncryptData_IsTheEncryptionOfTheData(CKM mechanism) => MechanismCoverageTestCases.Assert_AesEncryptData_IsTheEncryptionOfTheData(_backend, mechanism);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [InlineData(CKM.CKM_CAMELLIA_ECB_ENCRYPT_DATA)]
    [InlineData(CKM.CKM_CAMELLIA_CBC_ENCRYPT_DATA)]
    public void CamelliaEncryptData_IsTheEncryptionOfTheData(CKM mechanism) => MechanismCoverageTestCases.Assert_CamelliaEncryptData_IsTheEncryptionOfTheData(_backend, mechanism);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ConcatenateBaseAndKey_IsBothValues() => MechanismCoverageTestCases.Assert_ConcatenateBaseAndKey_IsBothValues(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [InlineData(CKM.CKM_CONCATENATE_BASE_AND_DATA)]
    [InlineData(CKM.CKM_CONCATENATE_DATA_AND_BASE)]
    [InlineData(CKM.CKM_XOR_BASE_AND_DATA)]
    public void StringDataDerivation(CKM mechanism) => MechanismCoverageTestCases.Assert_StringDataDerivation(_backend, mechanism);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.Extractions), MemberType = typeof(MechanismCoverageTestCases))]
    public void ExtractKeyFromKey_StartsAtTheBitGiven(string baseKey, int bit, int length) => MechanismCoverageTestCases.Assert_ExtractKeyFromKey_StartsAtTheBitGiven(_backend, baseKey, bit, length);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.AesFeedbackModes), MemberType = typeof(MechanismCoverageTestCases))]
    public void AesFeedbackMode_MatchesSp80038a(CKM mechanism) => MechanismCoverageTestCases.Assert_AesFeedbackMode_MatchesSp80038a(_backend, mechanism);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.CtsLengths), MemberType = typeof(MechanismCoverageTestCases))]
    public void AesCts_IsNistCiphertextStealing(int length) => MechanismCoverageTestCases.Assert_AesCts_IsNistCiphertextStealing(_backend, length);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void AesGmac_IsTheGcmTagOfTheData() => MechanismCoverageTestCases.Assert_AesGmac_IsTheGcmTagOfTheData(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.CamelliaModes), MemberType = typeof(MechanismCoverageTestCases))]
    public void Camellia_KnownAnswer(CKM mode) => MechanismCoverageTestCases.Assert_Camellia_KnownAnswer(_backend, mode);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Poly1305_Rfc8439Vector() => MechanismCoverageTestCases.Assert_Poly1305_Rfc8439Vector(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.KeyGenFamilies), MemberType = typeof(MechanismCoverageTestCases))]
    public void HmacKeyGen_MakesAKeyItsHmacTakes(string family) => MechanismCoverageTestCases.Assert_HmacKeyGen_MakesAKeyItsHmacTakes(_backend, family);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Sha512TKeyGen_MakesASha512THmacKey() => MechanismCoverageTestCases.Assert_Sha512TKeyGen_MakesASha512THmacKey(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.CamelliaKeyLengths), MemberType = typeof(MechanismCoverageTestCases))]
    public void CamelliaKeyGen_MakesAKeyCamelliaTakes(int length) => MechanismCoverageTestCases.Assert_CamelliaKeyGen_MakesAKeyCamelliaTakes(_backend, length);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Poly1305KeyGen_MakesAKeyPoly1305Takes() => MechanismCoverageTestCases.Assert_Poly1305KeyGen_MakesAKeyPoly1305Takes(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Salsa20KeyGen_MakesAKeySalsa20Takes() => MechanismCoverageTestCases.Assert_Salsa20KeyGen_MakesAKeySalsa20Takes(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.Pkcs1SignatureMechanisms), MemberType = typeof(MechanismCoverageTestCases))]
    public void RsaPkcs1Signature_IsEmsaPkcs1OverTheHash(CKM mechanism) => MechanismCoverageTestCases.Assert_RsaPkcs1Signature_IsEmsaPkcs1OverTheHash(_backend, mechanism);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.PssSignatureMechanisms), MemberType = typeof(MechanismCoverageTestCases))]
    public void RsaPssSignature_PassesEmsaPssVerify(CKM mechanism) => MechanismCoverageTestCases.Assert_RsaPssSignature_PassesEmsaPssVerify(_backend, mechanism);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.EcdsaSignatureMechanisms), MemberType = typeof(MechanismCoverageTestCases))]
    public void EcdsaSignature_VerifiesOverTheHash(CKM mechanism) => MechanismCoverageTestCases.Assert_EcdsaSignature_VerifiesOverTheHash(_backend, mechanism);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void RsaX931_KeyPairSignsAsX931Says() => MechanismCoverageTestCases.Assert_RsaX931_KeyPairSignsAsX931Says(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Rsa9796_SignsWithMessageRecovery() => MechanismCoverageTestCases.Assert_Rsa9796_SignsWithMessageRecovery(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void RsaPkcs_SignRecover_IsThePkcs1Signature() => MechanismCoverageTestCases.Assert_RsaPkcs_SignRecover_IsThePkcs1Signature(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(MechanismCoverageTestCases.WrapMechanisms), MemberType = typeof(MechanismCoverageTestCases))]
    public void Wrap_IsTheEncryptionOfTheKeyValue(string mechanism) => MechanismCoverageTestCases.Assert_Wrap_IsTheEncryptionOfTheKeyValue(_backend, mechanism);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void RsaPkcs_EncapsulatesAPkcs1EncryptedSecret() => MechanismCoverageTestCases.Assert_RsaPkcs_EncapsulatesAPkcs1EncryptedSecret(_backend);
}
