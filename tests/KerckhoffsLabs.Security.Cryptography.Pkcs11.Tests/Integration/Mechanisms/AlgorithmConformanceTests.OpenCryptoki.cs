using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>AlgorithmConformance over opencryptoki — thin wrapper over <see cref="AlgorithmConformanceTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class AlgorithmConformanceTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void RsaPss_SignatureCarriesTheSaltAndMaskAsked() => AlgorithmConformanceTestCases.Assert_RsaPss_SignatureCarriesTheSaltAndMaskAsked(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void RsaPss_SaltLength_IsBoundedByTheModulus() => AlgorithmConformanceTestCases.Assert_RsaPss_SaltLength_IsBoundedByTheModulus(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void RsaOaep_IsRandomised() => AlgorithmConformanceTestCases.Assert_RsaOaep_IsRandomised(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void RsaOaep_TransportsAnAesKey() => AlgorithmConformanceTestCases.Assert_RsaOaep_TransportsAnAesKey(_backend);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.EdDsaVariants), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void EdDsa_Rfc8032Variant_SignsTheKnownAnswer(string variant) => AlgorithmConformanceTestCases.Assert_EdDsa_Rfc8032Variant_SignsTheKnownAnswer(_backend, variant);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.EcdsaCurves), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void Ecdsa_OnTheCurve_VerifiesUnderBcl(string curve) => AlgorithmConformanceTestCases.Assert_Ecdsa_OnTheCurve_VerifiesUnderBcl(_backend, curve);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.DigestVectors), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void Digest_KnownAnswer(CKM mechanism, string message, string expected) => AlgorithmConformanceTestCases.Assert_Digest_KnownAnswer(_backend, mechanism, message, expected);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(AlgorithmConformanceTestCases.EmptyDigestVectors), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void Digest_OfNothing_KnownAnswer(CKM mechanism, string message, string expected) => AlgorithmConformanceTestCases.Assert_Digest_KnownAnswer(_backend, mechanism, message, expected);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void DigestKey_IsTheDigestOfTheKeysValue() => AlgorithmConformanceTestCases.Assert_DigestKey_IsTheDigestOfTheKeysValue(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Ecdh_Sha256Kdf_IsX963OverZAndTheSharedData() => AlgorithmConformanceTestCases.Assert_Ecdh_Sha256Kdf_IsX963OverZAndTheSharedData(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void EcdhCofactor_OnP256_AgreesThePlainSecret() => AlgorithmConformanceTestCases.Assert_EcdhCofactor_OnP256_AgreesThePlainSecret(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void X25519_LowOrderPeer_IsRefused() => AlgorithmConformanceTestCases.Assert_X25519_LowOrderPeer_IsRefused(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void X448_Rfc7748_AgreesTheKnownSecret() => AlgorithmConformanceTestCases.Assert_X448_Rfc7748_AgreesTheKnownSecret(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Hkdf_Sha512_MatchesBcl() => AlgorithmConformanceTestCases.Assert_Hkdf_Sha512_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Hkdf_SaltFromAKey_MatchesBcl() => AlgorithmConformanceTestCases.Assert_Hkdf_SaltFromAKey_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Sha256KeyDerivation_IsTheDigestOfTheBaseKey() => AlgorithmConformanceTestCases.Assert_Sha256KeyDerivation_IsTheDigestOfTheBaseKey(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void AesKeyWrap_ExplicitDefaultIv_GivesTheSameBlob() => AlgorithmConformanceTestCases.Assert_AesKeyWrap_ExplicitDefaultIv_GivesTheSameBlob(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void AesKeyWrap_UnwrapWithAGenericSecret_IsRefused() => AlgorithmConformanceTestCases.Assert_AesKeyWrap_UnwrapWithAGenericSecret_IsRefused(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void MlKem_DecapsulationUnderAnotherKey_GivesAnotherSecret() => AlgorithmConformanceTestCases.Assert_MlKem_DecapsulationUnderAnotherKey_GivesAnotherSecret(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void HashMlDsa_UnderAnotherHash_DoesNotVerify() => AlgorithmConformanceTestCases.Assert_HashMlDsa_UnderAnotherHash_DoesNotVerify(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void DigestState_SavedAndRestored_FinishesTheDigest() => AlgorithmConformanceTestCases.Assert_DigestState_SavedAndRestored_FinishesTheDigest(_backend, unsaveable: CKR.CKR_STATE_UNSAVEABLE);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void RsaOaep_UnwrapOfABlobNotKBytes_IsWrappedKeyLenRange() => AlgorithmConformanceTestCases.Assert_RsaOaep_UnwrapOfABlobNotKBytes_IsWrappedKeyLenRange(_backend);
}
