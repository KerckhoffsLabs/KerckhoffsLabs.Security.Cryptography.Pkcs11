using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>AlgorithmConformance over FreeHSM — thin wrapper over <see cref="AlgorithmConformanceTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class AlgorithmConformanceTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RsaPss_SignatureCarriesTheSaltAndMaskAsked() => AlgorithmConformanceTestCases.Assert_RsaPss_SignatureCarriesTheSaltAndMaskAsked(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RsaPss_SaltLength_IsBoundedByTheModulus() => AlgorithmConformanceTestCases.Assert_RsaPss_SaltLength_IsBoundedByTheModulus(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RsaOaep_IsRandomised() => AlgorithmConformanceTestCases.Assert_RsaOaep_IsRandomised(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RsaOaep_TransportsAnAesKey() => AlgorithmConformanceTestCases.Assert_RsaOaep_TransportsAnAesKey(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RsaPkcs1_Plaintext_IsBoundedByKMinus11() => AlgorithmConformanceTestCases.Assert_RsaPkcs1_Plaintext_IsBoundedByKMinus11(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.EdDsaVariants), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void EdDsa_Rfc8032Variant_SignsTheKnownAnswer(string variant) => AlgorithmConformanceTestCases.Assert_EdDsa_Rfc8032Variant_SignsTheKnownAnswer(_backend, variant);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.EcdsaCurves), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void Ecdsa_OnTheCurve_VerifiesUnderBcl(string curve) => AlgorithmConformanceTestCases.Assert_Ecdsa_OnTheCurve_VerifiesUnderBcl(_backend, curve);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.DigestVectors), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void Digest_KnownAnswer(CKM mechanism, string message, string expected) => AlgorithmConformanceTestCases.Assert_Digest_KnownAnswer(_backend, mechanism, message, expected);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.EmptyDigestVectors), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void Digest_OfNothing_KnownAnswer(CKM mechanism, string message, string expected) => AlgorithmConformanceTestCases.Assert_Digest_KnownAnswer(_backend, mechanism, message, expected);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void DigestKey_IsTheDigestOfTheKeysValue() => AlgorithmConformanceTestCases.Assert_DigestKey_IsTheDigestOfTheKeysValue(_backend);

    // FreeHSM refuses CKD_SHA256_KDF with CKR_ARGUMENTS_BAD.
    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Ecdh_Sha256Kdf_IsX963OverZAndTheSharedData() => AlgorithmConformanceTestCases.Assert_Ecdh_Sha256Kdf_IsX963OverZAndTheSharedData(_backend, refused: CKR.CKR_ARGUMENTS_BAD);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void EcdhCofactor_OnP256_AgreesThePlainSecret() => AlgorithmConformanceTestCases.Assert_EcdhCofactor_OnP256_AgreesThePlainSecret(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void X25519_LowOrderPeer_IsRefused() => AlgorithmConformanceTestCases.Assert_X25519_LowOrderPeer_IsRefused(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void X448_Rfc7748_AgreesTheKnownSecret() => AlgorithmConformanceTestCases.Assert_X448_Rfc7748_AgreesTheKnownSecret(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Hkdf_Sha512_MatchesBcl() => AlgorithmConformanceTestCases.Assert_Hkdf_Sha512_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Hkdf_SaltFromAKey_MatchesBcl() => AlgorithmConformanceTestCases.Assert_Hkdf_SaltFromAKey_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Sha256KeyDerivation_IsTheDigestOfTheBaseKey() => AlgorithmConformanceTestCases.Assert_Sha256KeyDerivation_IsTheDigestOfTheBaseKey(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void AesKeyWrap_ExplicitDefaultIv_GivesTheSameBlob() => AlgorithmConformanceTestCases.Assert_AesKeyWrap_ExplicitDefaultIv_GivesTheSameBlob(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.AesKeyWrapTampering), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void AesKeyWrap_TamperedBlob_IsRefused(string tampering) => AlgorithmConformanceTestCases.Assert_AesKeyWrap_TamperedBlob_IsRefused(_backend, tampering);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void AesKeyWrap_UnwrapWithAGenericSecret_IsRefused() => AlgorithmConformanceTestCases.Assert_AesKeyWrap_UnwrapWithAGenericSecret_IsRefused(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void MlKem_DecapsulationUnderAnotherKey_GivesAnotherSecret() => AlgorithmConformanceTestCases.Assert_MlKem_DecapsulationUnderAnotherKey_GivesAnotherSecret(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void HashMlDsa_UnderAnotherHash_DoesNotVerify() => AlgorithmConformanceTestCases.Assert_HashMlDsa_UnderAnotherHash_DoesNotVerify(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void DigestState_SavedAndRestored_FinishesTheDigest() => AlgorithmConformanceTestCases.Assert_DigestState_SavedAndRestored_FinishesTheDigest(_backend, unsaveable: CKR.CKR_FUNCTION_NOT_SUPPORTED);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RsaOaep_UnwrapOfABlobNotKBytes_IsWrappedKeyLenRange() => AlgorithmConformanceTestCases.Assert_RsaOaep_UnwrapOfABlobNotKBytes_IsWrappedKeyLenRange(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RsaX509_Verify_RequiresTheLeadingBytes() => AlgorithmConformanceTestCases.Assert_RsaX509_Verify_RequiresTheLeadingBytes(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RsaX509_Verify_OfDataLongerThanTheModulus_IsRefused() => AlgorithmConformanceTestCases.Assert_RsaX509_Verify_OfDataLongerThanTheModulus_IsRefused(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void DigestKey_OfAPrivateKey_IsKeyIndigestible() => AlgorithmConformanceTestCases.Assert_DigestKey_OfAPrivateKey_IsKeyIndigestible(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.OperationStateMisuses), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void OperationState_Misuse_IsRefused(string misuse) => AlgorithmConformanceTestCases.Assert_OperationState_Misuse_IsRefused(_backend, misuse);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.PssParameterFaults), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void RsaPss_ParameterOutOfRange_IsMechanismParamInvalid(string fault)
    {
        if (fault == "hashAlg SHA-384" && !FreeHsmBackendFixture.FreeHsmRefusesAMismatchedPssHash)
            Assert.Skip("FreeHSM signs CKM_SHA256_RSA_PKCS_PSS with SHA-256 whatever hashAlg says");
        AlgorithmConformanceTestCases.Assert_RsaPss_ParameterOutOfRange_IsMechanismParamInvalid(_backend, fault);
    }

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.EcdhParameterRefusalAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "FreeHSM takes CKD_NULL shared data and a CKA_VALUE_LEN above the secret, and refuses a malformed peer as an attribute")]
    [MemberData(nameof(AlgorithmConformanceTestCases.EcdhParameterFaults), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void Ecdh_ParameterOutOfRange_IsRefused(string fault) => AlgorithmConformanceTestCases.Assert_Ecdh_ParameterOutOfRange_IsRefused(_backend, fault);
}
