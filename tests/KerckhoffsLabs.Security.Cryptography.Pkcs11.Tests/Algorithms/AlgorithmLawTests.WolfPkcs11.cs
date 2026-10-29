using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>The algorithm laws over wolfPKCS11 — thin wrapper over <see cref="AlgorithmLawTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class AlgorithmLawTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void AesGcm_OpensWhatItSeals_RejectsAnyBitFlip() => AlgorithmLawTestCases.Assert_AesGcm_OpensWhatItSeals_RejectsAnyBitFlip(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void AesCcm_OpensWhatItSeals_RejectsAnyBitFlip() => AlgorithmLawTestCases.Assert_AesCcm_OpensWhatItSeals_RejectsAnyBitFlip(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ChaCha20Poly1305_OpensWhatItSeals_RejectsAnyBitFlip() => AlgorithmLawTestCases.Assert_ChaCha20Poly1305_OpensWhatItSeals_RejectsAnyBitFlip(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    [MemberData(nameof(PropertyTestSupport.Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Hkdf_ShorterOutputIsAPrefix(string hashName) => AlgorithmLawTestCases.Assert_Hkdf_ShorterOutputIsAPrefix(_backend, hashName);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Pbkdf2_ShorterOutputIsAPrefix(string hashName) => AlgorithmLawTestCases.Assert_Pbkdf2_ShorterOutputIsAPrefix(_backend, hashName);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Sp800108HmacCounter_OutputLengthIsBound(string hashName) => AlgorithmLawTestCases.Assert_Sp800108HmacCounter_OutputLengthIsBound(_backend, hashName);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(PropertyTestSupport.RsaSignatureSchemes), MemberType = typeof(PropertyTestSupport))]
    public void RsaSignature_VerifiesOnlyUnaltered(string padding, string hashName)
    {
        if (!WolfPkcs11BackendFixture.WolfPkcs11RejectsMalformedSignatures)
            Assert.Skip("wolfPKCS11 answers a malformed signature with CKR_FUNCTION_FAILED");
        AlgorithmLawTestCases.Assert_RsaSignature_VerifiesOnlyUnaltered(_backend, padding, hashName);
    }

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void RsaOaep_OpensWhatItSeals(string hashName) => AlgorithmLawTestCases.Assert_RsaOaep_OpensWhatItSeals(_backend, hashName, emptyData: WolfPkcs11BackendFixture.WolfPkcs11AcceptsEmptyOaepMessage);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(PropertyTestSupport.CurvesAndSignatureFormats), MemberType = typeof(PropertyTestSupport))]
    public void EcdsaSignature_VerifiesOnlyUnaltered(string curve, DSASignatureFormat format)
    {
        // Only P-521 encodes r and s with bits above the curve order (521 bits in 66 bytes) for a flip to land in.
        if (curve == "P-521" && !WolfPkcs11BackendFixture.WolfPkcs11RejectsMalformedSignatures)
            Assert.Skip("wolfPKCS11 answers a malformed signature with CKR_FUNCTION_FAILED");
        AlgorithmLawTestCases.Assert_EcdsaSignature_VerifiesOnlyUnaltered(_backend, curve, format);
    }

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    [MemberData(nameof(PropertyTestSupport.Curves), MemberType = typeof(PropertyTestSupport))]
    public void Ecdh_TokenKeysAgree(string curve) => AlgorithmLawTestCases.Assert_Ecdh_TokenKeysAgree(_backend, curve);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.MalformedSignatureRejectionAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 answers a malformed signature with CKR_FUNCTION_FAILED")]
    [MemberData(nameof(PropertyTestSupport.MlDsaParameterSets), MemberType = typeof(PropertyTestSupport))]
    public void MlDsaSignature_VerifiesOnlyUnaltered(CkpMlDsa parameterSet) => AlgorithmLawTestCases.Assert_MlDsaSignature_VerifiesOnlyUnaltered(_backend, parameterSet);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void SlhDsaSignature_VerifiesOnlyUnaltered() => AlgorithmLawTestCases.Assert_SlhDsaSignature_VerifiesOnlyUnaltered(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(PropertyTestSupport.MlKemParameterSets), MemberType = typeof(PropertyTestSupport))]
    public void MlKem_DecapsulatesItsOwn_RejectsAnyBitFlipImplicitly(CkpMlKem parameterSet) => AlgorithmLawTestCases.Assert_MlKem_DecapsulatesItsOwn_RejectsAnyBitFlipImplicitly(_backend, parameterSet);
}
