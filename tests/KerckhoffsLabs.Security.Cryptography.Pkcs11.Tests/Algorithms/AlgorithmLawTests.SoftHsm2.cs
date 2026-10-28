using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>The algorithm laws over SoftHsm2 — thin wrapper over <see cref="AlgorithmLawTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class AlgorithmLawTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void AesGcm_OpensWhatItSeals_RejectsAnyBitFlip() => AlgorithmLawTestCases.Assert_AesGcm_OpensWhatItSeals_RejectsAnyBitFlip(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void AesCcm_OpensWhatItSeals_RejectsAnyBitFlip() => AlgorithmLawTestCases.Assert_AesCcm_OpensWhatItSeals_RejectsAnyBitFlip(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ChaCha20Poly1305_OpensWhatItSeals_RejectsAnyBitFlip() => AlgorithmLawTestCases.Assert_ChaCha20Poly1305_OpensWhatItSeals_RejectsAnyBitFlip(_backend);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Hkdf_ShorterOutputIsAPrefix(string hashName) => AlgorithmLawTestCases.Assert_Hkdf_ShorterOutputIsAPrefix(_backend, hashName);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Pbkdf2_ShorterOutputIsAPrefix(string hashName) => AlgorithmLawTestCases.Assert_Pbkdf2_ShorterOutputIsAPrefix(_backend, hashName);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Sp800108HmacCounter_OutputLengthIsBound(string hashName) => AlgorithmLawTestCases.Assert_Sp800108HmacCounter_OutputLengthIsBound(_backend, hashName);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.RsaSignatureSchemes), MemberType = typeof(PropertyTestSupport))]
    public void RsaSignature_VerifiesOnlyUnaltered(string padding, string hashName) => AlgorithmLawTestCases.Assert_RsaSignature_VerifiesOnlyUnaltered(_backend, padding, hashName);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void RsaOaep_OpensWhatItSeals(string hashName) => AlgorithmLawTestCases.Assert_RsaOaep_OpensWhatItSeals(_backend, hashName);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.CurvesAndSignatureFormats), MemberType = typeof(PropertyTestSupport))]
    public void EcdsaSignature_VerifiesOnlyUnaltered(string curve, DSASignatureFormat format) => AlgorithmLawTestCases.Assert_EcdsaSignature_VerifiesOnlyUnaltered(_backend, curve, format);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Curves), MemberType = typeof(PropertyTestSupport))]
    public void Ecdh_TokenKeysAgree(string curve) => AlgorithmLawTestCases.Assert_Ecdh_TokenKeysAgree(_backend, curve);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.MlDsaParameterSets), MemberType = typeof(PropertyTestSupport))]
    public void MlDsaSignature_VerifiesOnlyUnaltered(CkpMlDsa parameterSet) => AlgorithmLawTestCases.Assert_MlDsaSignature_VerifiesOnlyUnaltered(_backend, parameterSet);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void SlhDsaSignature_VerifiesOnlyUnaltered() => AlgorithmLawTestCases.Assert_SlhDsaSignature_VerifiesOnlyUnaltered(_backend);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.MlKemParameterSets), MemberType = typeof(PropertyTestSupport))]
    public void MlKem_DecapsulatesItsOwn_RejectsAnyBitFlipImplicitly(CkpMlKem parameterSet) => AlgorithmLawTestCases.Assert_MlKem_DecapsulatesItsOwn_RejectsAnyBitFlipImplicitly(_backend, parameterSet);
}
