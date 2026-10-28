using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>The algorithm laws over NSS — thin wrapper over <see cref="AlgorithmLawTestCases"/>.</summary>
[Collection("Nss")]
public sealed class AlgorithmLawTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void AesGcm_OpensWhatItSeals_RejectsAnyBitFlip()
    {
        _backend.RequireAesGcm();
        AlgorithmLawTestCases.Assert_AesGcm_OpensWhatItSeals_RejectsAnyBitFlip(_backend);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void AesCcm_OpensWhatItSeals_RejectsAnyBitFlip() => AlgorithmLawTestCases.Assert_AesCcm_OpensWhatItSeals_RejectsAnyBitFlip(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ChaCha20Poly1305_OpensWhatItSeals_RejectsAnyBitFlip() => AlgorithmLawTestCases.Assert_ChaCha20Poly1305_OpensWhatItSeals_RejectsAnyBitFlip(_backend);

    // NSS refuses to read a derived value back; see NssBackendFixture.SupportsExtractableDerive.
    [Theory(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    [MemberData(nameof(PropertyTestSupport.Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Hkdf_ShorterOutputIsAPrefix(string hashName) => AlgorithmLawTestCases.Assert_Hkdf_ShorterOutputIsAPrefix(_backend, hashName);

    // NSS refuses to read a derived value back; see NssBackendFixture.SupportsExtractableDerive.
    [Theory(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Pbkdf2_ShorterOutputIsAPrefix(string hashName) => AlgorithmLawTestCases.Assert_Pbkdf2_ShorterOutputIsAPrefix(_backend, hashName);

    // NSS refuses to read a derived value back; see NssBackendFixture.SupportsExtractableDerive.
    [Theory(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Sp800108HmacCounter_OutputLengthIsBound(string hashName) => AlgorithmLawTestCases.Assert_Sp800108HmacCounter_OutputLengthIsBound(_backend, hashName);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(PropertyTestSupport.RsaSignatureSchemes), MemberType = typeof(PropertyTestSupport))]
    public void RsaSignature_VerifiesOnlyUnaltered(string padding, string hashName) => AlgorithmLawTestCases.Assert_RsaSignature_VerifiesOnlyUnaltered(_backend, padding, hashName);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void RsaOaep_OpensWhatItSeals(string hashName) => AlgorithmLawTestCases.Assert_RsaOaep_OpensWhatItSeals(_backend, hashName);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(PropertyTestSupport.CurvesAndSignatureFormats), MemberType = typeof(PropertyTestSupport))]
    public void EcdsaSignature_VerifiesOnlyUnaltered(string curve, DSASignatureFormat format) => AlgorithmLawTestCases.Assert_EcdsaSignature_VerifiesOnlyUnaltered(_backend, curve, format);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(PropertyTestSupport.Curves), MemberType = typeof(PropertyTestSupport))]
    public void Ecdh_TokenKeysAgree(string curve) => AlgorithmLawTestCases.Assert_Ecdh_TokenKeysAgree(_backend, curve);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(PropertyTestSupport.MlDsaParameterSets), MemberType = typeof(PropertyTestSupport))]
    public void MlDsaSignature_VerifiesOnlyUnaltered(CkpMlDsa parameterSet) => AlgorithmLawTestCases.Assert_MlDsaSignature_VerifiesOnlyUnaltered(_backend, parameterSet);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void SlhDsaSignature_VerifiesOnlyUnaltered() => AlgorithmLawTestCases.Assert_SlhDsaSignature_VerifiesOnlyUnaltered(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(PropertyTestSupport.MlKemParameterSets), MemberType = typeof(PropertyTestSupport))]
    public void MlKem_DecapsulatesItsOwn_RejectsAnyBitFlipImplicitly(CkpMlKem parameterSet) => AlgorithmLawTestCases.Assert_MlKem_DecapsulatesItsOwn_RejectsAnyBitFlipImplicitly(_backend, parameterSet);
}
