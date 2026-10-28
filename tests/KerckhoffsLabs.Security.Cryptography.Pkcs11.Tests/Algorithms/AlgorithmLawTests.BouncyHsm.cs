using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>The algorithm laws over BouncyHsm — thin wrapper over <see cref="AlgorithmLawTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class AlgorithmLawTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesGcm_OpensWhatItSeals_RejectsAnyBitFlip() => AlgorithmLawTestCases.Assert_AesGcm_OpensWhatItSeals_RejectsAnyBitFlip(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void AesCcm_OpensWhatItSeals_RejectsAnyBitFlip() => AlgorithmLawTestCases.Assert_AesCcm_OpensWhatItSeals_RejectsAnyBitFlip(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ChaCha20Poly1305_OpensWhatItSeals_RejectsAnyBitFlip() => AlgorithmLawTestCases.Assert_ChaCha20Poly1305_OpensWhatItSeals_RejectsAnyBitFlip(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Hkdf_ShorterOutputIsAPrefix(string hashName) => AlgorithmLawTestCases.Assert_Hkdf_ShorterOutputIsAPrefix(_backend, hashName);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Pbkdf2_ShorterOutputIsAPrefix(string hashName) => AlgorithmLawTestCases.Assert_Pbkdf2_ShorterOutputIsAPrefix(_backend, hashName);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Sp800108HmacCounter_OutputLengthIsBound(string hashName) => AlgorithmLawTestCases.Assert_Sp800108HmacCounter_OutputLengthIsBound(_backend, hashName);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.RsaSignatureSchemes), MemberType = typeof(PropertyTestSupport))]
    public void RsaSignature_VerifiesOnlyUnaltered(string padding, string hashName) => AlgorithmLawTestCases.Assert_RsaSignature_VerifiesOnlyUnaltered(_backend, padding, hashName);

    // No empty message: the server's OAEP encryption of one returns no ciphertext at all (BouncyCastle's
    // BufferedAsymmetricBlockCipher gives empty output for empty input), where RFC 8017 gives a
    // modulus-length one, so the token cannot open it.
    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void RsaOaep_OpensWhatItSeals(string hashName) => AlgorithmLawTestCases.Assert_RsaOaep_OpensWhatItSeals(_backend, hashName, emptyData: false);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.CurvesAndSignatureFormats), MemberType = typeof(PropertyTestSupport))]
    public void EcdsaSignature_VerifiesOnlyUnaltered(string curve, DSASignatureFormat format) => AlgorithmLawTestCases.Assert_EcdsaSignature_VerifiesOnlyUnaltered(_backend, curve, format);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.Curves), MemberType = typeof(PropertyTestSupport))]
    public void Ecdh_TokenKeysAgree(string curve) => AlgorithmLawTestCases.Assert_Ecdh_TokenKeysAgree(_backend, curve);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.MlDsaParameterSets), MemberType = typeof(PropertyTestSupport))]
    public void MlDsaSignature_VerifiesOnlyUnaltered(CkpMlDsa parameterSet) => AlgorithmLawTestCases.Assert_MlDsaSignature_VerifiesOnlyUnaltered(_backend, parameterSet);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SlhDsaSignature_VerifiesOnlyUnaltered() => AlgorithmLawTestCases.Assert_SlhDsaSignature_VerifiesOnlyUnaltered(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(PropertyTestSupport.MlKemParameterSets), MemberType = typeof(PropertyTestSupport))]
    public void MlKem_DecapsulatesItsOwn_RejectsAnyBitFlipImplicitly(CkpMlKem parameterSet) => AlgorithmLawTestCases.Assert_MlKem_DecapsulatesItsOwn_RejectsAnyBitFlipImplicitly(_backend, parameterSet);
}
