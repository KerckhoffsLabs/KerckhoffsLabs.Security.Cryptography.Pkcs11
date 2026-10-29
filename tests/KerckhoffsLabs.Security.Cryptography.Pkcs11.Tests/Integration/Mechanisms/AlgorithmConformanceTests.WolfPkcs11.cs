using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>AlgorithmConformance over wolfPKCS11 — thin wrapper over <see cref="AlgorithmConformanceTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class AlgorithmConformanceTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void RsaPss_SignatureCarriesTheSaltAndMaskAsked() => AlgorithmConformanceTestCases.Assert_RsaPss_SignatureCarriesTheSaltAndMaskAsked(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void RsaPss_SaltLength_IsBoundedByTheModulus() => AlgorithmConformanceTestCases.Assert_RsaPss_SaltLength_IsBoundedByTheModulus(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void RsaOaep_IsRandomised() => AlgorithmConformanceTestCases.Assert_RsaOaep_IsRandomised(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void RsaOaep_TransportsAnAesKey() => AlgorithmConformanceTestCases.Assert_RsaOaep_TransportsAnAesKey(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void RsaPkcs1_Plaintext_IsBoundedByKMinus11() => AlgorithmConformanceTestCases.Assert_RsaPkcs1_Plaintext_IsBoundedByKMinus11(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(AlgorithmConformanceTestCases.EdDsaVariants), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void EdDsa_Rfc8032Variant_SignsTheKnownAnswer(string variant) => AlgorithmConformanceTestCases.Assert_EdDsa_Rfc8032Variant_SignsTheKnownAnswer(_backend, variant);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(AlgorithmConformanceTestCases.EcdsaCurves), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void Ecdsa_OnTheCurve_VerifiesUnderBcl(string curve) => AlgorithmConformanceTestCases.Assert_Ecdsa_OnTheCurve_VerifiesUnderBcl(_backend, curve);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(AlgorithmConformanceTestCases.DigestVectors), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void Digest_KnownAnswer(CKM mechanism, string message, string expected) => AlgorithmConformanceTestCases.Assert_Digest_KnownAnswer(_backend, mechanism, message, expected);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(AlgorithmConformanceTestCases.EmptyDigestVectors), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void Digest_OfNothing_KnownAnswer(CKM mechanism, string message, string expected) => AlgorithmConformanceTestCases.Assert_Digest_KnownAnswer(_backend, mechanism, message, expected);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void DigestKey_IsTheDigestOfTheKeysValue() => AlgorithmConformanceTestCases.Assert_DigestKey_IsTheDigestOfTheKeysValue(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Ecdh_Sha256Kdf_IsX963OverZAndTheSharedData() => AlgorithmConformanceTestCases.Assert_Ecdh_Sha256Kdf_IsX963OverZAndTheSharedData(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void EcdhCofactor_OnP256_AgreesThePlainSecret() => AlgorithmConformanceTestCases.Assert_EcdhCofactor_OnP256_AgreesThePlainSecret(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void X25519_LowOrderPeer_IsRefused() => AlgorithmConformanceTestCases.Assert_X25519_LowOrderPeer_IsRefused(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void X448_Rfc7748_AgreesTheKnownSecret() => AlgorithmConformanceTestCases.Assert_X448_Rfc7748_AgreesTheKnownSecret(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Hkdf_Sha512_MatchesBcl() => AlgorithmConformanceTestCases.Assert_Hkdf_Sha512_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Hkdf_SaltFromAKey_MatchesBcl() => AlgorithmConformanceTestCases.Assert_Hkdf_SaltFromAKey_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Sha256KeyDerivation_IsTheDigestOfTheBaseKey() => AlgorithmConformanceTestCases.Assert_Sha256KeyDerivation_IsTheDigestOfTheBaseKey(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void AesKeyWrap_ExplicitDefaultIv_GivesTheSameBlob() => AlgorithmConformanceTestCases.Assert_AesKeyWrap_ExplicitDefaultIv_GivesTheSameBlob(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(AlgorithmConformanceTestCases.AesKeyWrapTampering), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void AesKeyWrap_TamperedBlob_IsRefused(string tampering)
    {
        if (tampering == "20 bytes" && !WolfPkcs11BackendFixture.WolfPkcs11RefusesAKeyWrapBlobByItsLength)
            Assert.Skip("wolfPKCS11 answers an AES key wrap blob of a partial semiblock with CKR_WRAPPED_KEY_INVALID");
        AlgorithmConformanceTestCases.Assert_AesKeyWrap_TamperedBlob_IsRefused(_backend, tampering);
    }

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void AesKeyWrap_UnwrapWithAGenericSecret_IsRefused() => AlgorithmConformanceTestCases.Assert_AesKeyWrap_UnwrapWithAGenericSecret_IsRefused(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void MlKem_DecapsulationUnderAnotherKey_GivesAnotherSecret() => AlgorithmConformanceTestCases.Assert_MlKem_DecapsulationUnderAnotherKey_GivesAnotherSecret(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void HashMlDsa_UnderAnotherHash_DoesNotVerify() => AlgorithmConformanceTestCases.Assert_HashMlDsa_UnderAnotherHash_DoesNotVerify(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void DigestState_SavedAndRestored_FinishesTheDigest() => AlgorithmConformanceTestCases.Assert_DigestState_SavedAndRestored_FinishesTheDigest(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void RsaOaep_UnwrapOfABlobNotKBytes_IsWrappedKeyLenRange() => AlgorithmConformanceTestCases.Assert_RsaOaep_UnwrapOfABlobNotKBytes_IsWrappedKeyLenRange(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void RsaX509_Verify_RequiresTheLeadingBytes() => AlgorithmConformanceTestCases.Assert_RsaX509_Verify_RequiresTheLeadingBytes(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.OverlongRawRsaVerifyAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 answers an over-long raw RSA C_Verify with CKR_FUNCTION_FAILED")]
    public void RsaX509_Verify_OfDataLongerThanTheModulus_IsRefused() => AlgorithmConformanceTestCases.Assert_RsaX509_Verify_OfDataLongerThanTheModulus_IsRefused(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void DigestKey_OfAPrivateKey_IsKeyIndigestible() => AlgorithmConformanceTestCases.Assert_DigestKey_OfAPrivateKey_IsKeyIndigestible(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(AlgorithmConformanceTestCases.OperationStateMisuses), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void OperationState_Misuse_IsRefused(string misuse) => AlgorithmConformanceTestCases.Assert_OperationState_Misuse_IsRefused(_backend, misuse);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(AlgorithmConformanceTestCases.PssParameterFaults), MemberType = typeof(AlgorithmConformanceTestCases))]
    public void RsaPss_ParameterOutOfRange_IsMechanismParamInvalid(string fault) => AlgorithmConformanceTestCases.Assert_RsaPss_ParameterOutOfRange_IsMechanismParamInvalid(_backend, fault);
}
