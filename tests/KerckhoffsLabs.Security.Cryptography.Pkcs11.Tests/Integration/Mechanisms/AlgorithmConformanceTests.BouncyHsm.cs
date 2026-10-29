using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>AlgorithmConformance over BouncyHsm — thin wrapper over <see cref="AlgorithmConformanceTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class AlgorithmConformanceTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void RsaPss_SignatureCarriesTheSaltAndMaskAsked() => AlgorithmConformanceTestCases.Assert_RsaPss_SignatureCarriesTheSaltAndMaskAsked(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void RsaPss_SaltLength_IsBoundedByTheModulus() => AlgorithmConformanceTestCases.Assert_RsaPss_SaltLength_IsBoundedByTheModulus(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void RsaOaep_IsRandomised() => AlgorithmConformanceTestCases.Assert_RsaOaep_IsRandomised(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void RsaOaep_TransportsAnAesKey() => AlgorithmConformanceTestCases.Assert_RsaOaep_TransportsAnAesKey(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void RsaPkcs1_Plaintext_IsBoundedByKMinus11() => AlgorithmConformanceTestCases.Assert_RsaPkcs1_Plaintext_IsBoundedByKMinus11(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.EdDsaVariants), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void EdDsa_Rfc8032Variant_SignsTheKnownAnswer(string variant) => AlgorithmConformanceTestCases.Assert_EdDsa_Rfc8032Variant_SignsTheKnownAnswer(_backend, variant);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.EcdsaCurves), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void Ecdsa_OnTheCurve_VerifiesUnderBcl(string curve) => AlgorithmConformanceTestCases.Assert_Ecdsa_OnTheCurve_VerifiesUnderBcl(_backend, curve);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.DigestVectors), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void Digest_KnownAnswer(CKM mechanism, string message, string expected) => AlgorithmConformanceTestCases.Assert_Digest_KnownAnswer(_backend, mechanism, message, expected);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.EmptyDigestAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm answers a digest of empty data with CKR_DATA_LEN_RANGE")]
    [MemberData(nameof(AlgorithmConformanceTestCases.EmptyDigestVectors), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void Digest_OfNothing_KnownAnswer(CKM mechanism, string message, string expected) => AlgorithmConformanceTestCases.Assert_Digest_KnownAnswer(_backend, mechanism, message, expected);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void DigestKey_IsTheDigestOfTheKeysValue() => AlgorithmConformanceTestCases.Assert_DigestKey_IsTheDigestOfTheKeysValue(_backend);

    // BouncyHsm's CKD_SHA256_KDF counts from 0, not from 1 as ANSI X9.63 does, so its keys differ from every other module's.
    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Ecdh_Sha256Kdf_IsX963OverZAndTheSharedData() => AlgorithmConformanceTestCases.Assert_Ecdh_Sha256Kdf_IsX963OverZAndTheSharedData(_backend, counterStartsAtZero: true);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EcdhCofactor_OnP256_AgreesThePlainSecret() => AlgorithmConformanceTestCases.Assert_EcdhCofactor_OnP256_AgreesThePlainSecret(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void X25519_LowOrderPeer_IsRefused() => AlgorithmConformanceTestCases.Assert_X25519_LowOrderPeer_IsRefused(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void X448_Rfc7748_AgreesTheKnownSecret() => AlgorithmConformanceTestCases.Assert_X448_Rfc7748_AgreesTheKnownSecret(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Hkdf_Sha512_MatchesBcl() => AlgorithmConformanceTestCases.Assert_Hkdf_Sha512_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Hkdf_SaltFromAKey_MatchesBcl() => AlgorithmConformanceTestCases.Assert_Hkdf_SaltFromAKey_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Sha256KeyDerivation_IsTheDigestOfTheBaseKey() => AlgorithmConformanceTestCases.Assert_Sha256KeyDerivation_IsTheDigestOfTheBaseKey(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesKeyWrap_ExplicitDefaultIv_GivesTheSameBlob() => AlgorithmConformanceTestCases.Assert_AesKeyWrap_ExplicitDefaultIv_GivesTheSameBlob(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.AesKeyWrapTampering), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void AesKeyWrap_TamperedBlob_IsRefused(string tampering) => AlgorithmConformanceTestCases.Assert_AesKeyWrap_TamperedBlob_IsRefused(_backend, tampering);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesKeyWrap_UnwrapWithAGenericSecret_IsRefused() => AlgorithmConformanceTestCases.Assert_AesKeyWrap_UnwrapWithAGenericSecret_IsRefused(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void MlKem_DecapsulationUnderAnotherKey_GivesAnotherSecret() => AlgorithmConformanceTestCases.Assert_MlKem_DecapsulationUnderAnotherKey_GivesAnotherSecret(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void HashMlDsa_UnderAnotherHash_DoesNotVerify() => AlgorithmConformanceTestCases.Assert_HashMlDsa_UnderAnotherHash_DoesNotVerify(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void DigestState_SavedAndRestored_FinishesTheDigest() => AlgorithmConformanceTestCases.Assert_DigestState_SavedAndRestored_FinishesTheDigest(_backend, unsaveable: CKR.CKR_FUNCTION_NOT_SUPPORTED);
}
