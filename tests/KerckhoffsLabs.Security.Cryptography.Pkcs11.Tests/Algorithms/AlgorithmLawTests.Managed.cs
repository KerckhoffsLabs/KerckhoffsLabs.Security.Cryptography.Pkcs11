using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// The algorithm laws of <see cref="AlgorithmLawTestCases"/> over the in-process <c>ManagedSoftToken</c>.
/// The token computes with the BCL itself, so here the laws test the adapters and the marshalling between
/// them and a module rather than an independent implementation; the real backends supply that. It runs on
/// every CI leg, without a native token.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class AlgorithmLawTests_Managed
{
    [Fact]
    public void AesGcm_OpensWhatItSeals_RejectsAnyBitFlip()
    {
        using var backend = new ManagedBackend();
        AlgorithmLawTestCases.Assert_AesGcm_OpensWhatItSeals_RejectsAnyBitFlip(backend);
    }

    [Fact]
    public void AesCcm_OpensWhatItSeals_RejectsAnyBitFlip()
    {
        using var backend = new ManagedBackend();
        AlgorithmLawTestCases.Assert_AesCcm_OpensWhatItSeals_RejectsAnyBitFlip(backend);
    }

    [Fact]
    public void ChaCha20Poly1305_OpensWhatItSeals_RejectsAnyBitFlip()
    {
        using var backend = new ManagedBackend();
        AlgorithmLawTestCases.Assert_ChaCha20Poly1305_OpensWhatItSeals_RejectsAnyBitFlip(backend);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Hkdf_ShorterOutputIsAPrefix(string hashName)
    {
        // The token's HKDF runs the BCL's HMAC, which lacks SHA-3 on some hosts (macOS).
        Assert.SkipUnless(PropertyTestSupport.Hash(hashName).HostSupportsHmac(), $"Host BCL has no HMAC over {hashName}.");
        using var backend = new ManagedBackend();
        AlgorithmLawTestCases.Assert_Hkdf_ShorterOutputIsAPrefix(backend, hashName);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Pbkdf2_ShorterOutputIsAPrefix(string hashName)
    {
        using var backend = new ManagedBackend();
        AlgorithmLawTestCases.Assert_Pbkdf2_ShorterOutputIsAPrefix(backend, hashName);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Sp800108HmacCounter_OutputLengthIsBound(string hashName)
    {
        using var backend = new ManagedBackend();
        AlgorithmLawTestCases.Assert_Sp800108HmacCounter_OutputLengthIsBound(backend, hashName);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.RsaSignatureSchemes), MemberType = typeof(PropertyTestSupport))]
    public void RsaSignature_VerifiesOnlyUnaltered(string padding, string hashName)
    {
        using var backend = new ManagedBackend();
        AlgorithmLawTestCases.Assert_RsaSignature_VerifiesOnlyUnaltered(backend, padding, hashName);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void RsaOaep_OpensWhatItSeals(string hashName)
    {
        using var backend = new ManagedBackend();
        AlgorithmLawTestCases.Assert_RsaOaep_OpensWhatItSeals(backend, hashName);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.CurvesAndSignatureFormats), MemberType = typeof(PropertyTestSupport))]
    public void EcdsaSignature_VerifiesOnlyUnaltered(string curve, DSASignatureFormat format)
    {
        using var backend = new ManagedBackend();
        AlgorithmLawTestCases.Assert_EcdsaSignature_VerifiesOnlyUnaltered(backend, curve, format);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.Curves), MemberType = typeof(PropertyTestSupport))]
    public void Ecdh_TokenKeysAgree(string curve)
    {
        using var backend = new ManagedBackend();
        AlgorithmLawTestCases.Assert_Ecdh_TokenKeysAgree(backend, curve);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.MlDsaParameterSets), MemberType = typeof(PropertyTestSupport))]
    public void MlDsaSignature_VerifiesOnlyUnaltered(CkpMlDsa parameterSet)
    {
        using var backend = new ManagedBackend();
        AlgorithmLawTestCases.Assert_MlDsaSignature_VerifiesOnlyUnaltered(backend, parameterSet);
    }

    [Fact]
    public void SlhDsaSignature_VerifiesOnlyUnaltered()
    {
        using var backend = new ManagedBackend();
        AlgorithmLawTestCases.Assert_SlhDsaSignature_VerifiesOnlyUnaltered(backend);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.MlKemParameterSets), MemberType = typeof(PropertyTestSupport))]
    public void MlKem_DecapsulatesItsOwn_RejectsAnyBitFlipImplicitly(CkpMlKem parameterSet)
    {
        using var backend = new ManagedBackend();
        AlgorithmLawTestCases.Assert_MlKem_DecapsulatesItsOwn_RejectsAnyBitFlipImplicitly(backend, parameterSet);
    }
}
