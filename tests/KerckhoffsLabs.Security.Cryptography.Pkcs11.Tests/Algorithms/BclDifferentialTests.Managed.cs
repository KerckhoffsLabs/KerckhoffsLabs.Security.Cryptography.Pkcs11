using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// The differential properties of <see cref="BclDifferentialTestCases"/> over the in-process
/// <c>ManagedSoftToken</c>. The token computes with the BCL itself, so here the properties test the
/// adapters and the marshalling between them and a module (chunking, offsets, lengths, mechanism
/// parameters) rather than an independent implementation; the real backends supply that. It runs on
/// every CI leg, without a native token.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class BclDifferentialTests_Managed
{
    [Theory]
    [MemberData(nameof(PropertyTestSupport.Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Digest_MatchesBcl(string hashName)
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_Digest_MatchesBcl(backend, hashName);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Hmac_MatchesBcl(string hashName)
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_Hmac_MatchesBcl(backend, hashName);
    }

    [Theory]
    [InlineData(PaddingMode.None)]
    [InlineData(PaddingMode.PKCS7)]
    public void AesCbc_MatchesBcl(PaddingMode padding)
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_AesCbc_MatchesBcl(backend, padding);
    }

    [Theory]
    [InlineData(8)]
    [InlineData(128)]
    public void AesCfb_MatchesBcl(int feedbackSizeInBits)
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_AesCfb_MatchesBcl(backend, feedbackSizeInBits);
    }

    [Fact]
    public void AesKeyWrapPadded_MatchesBcl()
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_AesKeyWrapPadded_MatchesBcl(backend);
    }

    [Fact]
    public void AesGcm_MatchesBcl()
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_AesGcm_MatchesBcl(backend);
    }

    [Fact]
    public void AesCcm_MatchesBcl()
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_AesCcm_MatchesBcl(backend);
    }

    [Fact]
    public void ChaCha20Poly1305_MatchesBcl()
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_ChaCha20Poly1305_MatchesBcl(backend);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Hkdf_MatchesBcl(string hashName)
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_Hkdf_MatchesBcl(backend, hashName);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Sp800108HmacCounter_MatchesBcl(string hashName)
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_Sp800108HmacCounter_MatchesBcl(backend, hashName);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void Pbkdf2_MatchesBcl(string hashName)
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_Pbkdf2_MatchesBcl(backend, hashName);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.RsaSignatureSchemes), MemberType = typeof(PropertyTestSupport))]
    public void RsaSignData_VerifiesWithBcl(string padding, string hashName)
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_RsaSignData_VerifiesWithBcl(backend, padding, hashName);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.Sha2Hashes), MemberType = typeof(PropertyTestSupport))]
    public void RsaOaep_DecryptsBclCiphertext(string hashName)
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_RsaOaep_DecryptsBclCiphertext(backend, hashName);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.CurvesAndSignatureFormats), MemberType = typeof(PropertyTestSupport))]
    public void EcdsaSignData_VerifiesWithBcl(string curve, DSASignatureFormat format)
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_EcdsaSignData_VerifiesWithBcl(backend, curve, format);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.Curves), MemberType = typeof(PropertyTestSupport))]
    public void Ecdh_AgreesWithBcl(string curve)
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_Ecdh_AgreesWithBcl(backend, curve);
    }

    [Theory]
    [MemberData(nameof(PropertyTestSupport.MlDsaParameterSets), MemberType = typeof(PropertyTestSupport))]
    public void MlDsaSignData_VerifiesWithBcl(CkpMlDsa parameterSet)
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_MlDsaSignData_VerifiesWithBcl(backend, parameterSet);
    }

    [Fact]
    public void SlhDsaSignData_VerifiesWithBcl()
    {
        using var backend = new ManagedBackend();
        BclDifferentialTestCases.Assert_SlhDsaSignData_VerifiesWithBcl(backend);
    }
}
