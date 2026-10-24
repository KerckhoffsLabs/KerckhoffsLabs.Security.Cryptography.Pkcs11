using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>RSAPkcs11 over Kryoptic — thin wrapper over <see cref="RSAPkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class RSAPkcs11Tests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    [InlineData(8192)]
    [InlineData(16384)]
    public void SignVerifyData_AcrossKeySizes_RoundTrips(int modulusBits) => RSAPkcs11TestCases.Assert_SignVerifyData_AcrossKeySizes_RoundTrips(_backend, modulusBits);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void EncryptDecrypt_OaepModernHash_RoundTrips(string hash) => RSAPkcs11TestCases.Assert_EncryptDecrypt_OaepModernHash_RoundTrips(_backend, hash);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Ctor_NonRsaKey_Throws() => RSAPkcs11TestCases.Assert_Ctor_NonRsaKey_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignVerifyData_Pkcs1_RoundTrips() => RSAPkcs11TestCases.Assert_SignVerifyData_Pkcs1_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignVerifyData_Pss_RoundTrips() => RSAPkcs11TestCases.Assert_SignVerifyData_Pss_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignVerifyData_Sha224Pkcs1_UnderAllowInsecure_RoundTrips() => RSAPkcs11TestCases.Assert_SignVerifyData_Sha224Pkcs1_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignData_Sha224Pkcs1_WithoutAllowInsecure_Throws() => RSAPkcs11TestCases.Assert_SignData_Sha224Pkcs1_WithoutAllowInsecure_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignVerifyData_Sha224Pss_UnderAllowInsecure_RoundTrips() => RSAPkcs11TestCases.Assert_SignVerifyData_Sha224Pss_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignData_Sha224Pss_WithoutAllowInsecure_Throws() => RSAPkcs11TestCases.Assert_SignData_Sha224Pss_WithoutAllowInsecure_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignData_NullArguments_Throw() => RSAPkcs11TestCases.Assert_SignData_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignData_BadRange_Throws() => RSAPkcs11TestCases.Assert_SignData_BadRange_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void VerifyData_NullArguments_Throw() => RSAPkcs11TestCases.Assert_VerifyData_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void VerifyData_BadRange_Throws() => RSAPkcs11TestCases.Assert_VerifyData_BadRange_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void TrySignData_Span_VerifyData_Span_RoundTrips() => RSAPkcs11TestCases.Assert_TrySignData_Span_VerifyData_Span_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => RSAPkcs11TestCases.Assert_TrySignData_DestinationTooSmall_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void TrySignData_NullPadding_Throws() => RSAPkcs11TestCases.Assert_TrySignData_NullPadding_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void VerifyData_Span_NullPadding_Throws() => RSAPkcs11TestCases.Assert_VerifyData_Span_NullPadding_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void EncryptDecrypt_OaepSha1_RoundTrips() => RSAPkcs11TestCases.Assert_EncryptDecrypt_OaepSha1_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void EncryptDecrypt_OaepSha224_UnderAllowInsecure_RoundTrips() => RSAPkcs11TestCases.Assert_EncryptDecrypt_OaepSha224_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Encrypt_OaepSha224_WithoutAllowInsecure_Throws() => RSAPkcs11TestCases.Assert_Encrypt_OaepSha224_WithoutAllowInsecure_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void EncryptDecrypt_Pkcs1_UnderAllowInsecure_RoundTrips() => RSAPkcs11TestCases.Assert_EncryptDecrypt_Pkcs1_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Encrypt_NullArguments_Throw() => RSAPkcs11TestCases.Assert_Encrypt_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Decrypt_NullArguments_Throw() => RSAPkcs11TestCases.Assert_Decrypt_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Decrypt_Pkcs1InvalidPadding_NeverReturnsTheMessage() => RSAPkcs11TestCases.Assert_Decrypt_Pkcs1InvalidPadding_NeverReturnsTheMessage(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Decrypt_TamperedOaepCiphertext_Throws() => RSAPkcs11TestCases.Assert_Decrypt_TamperedOaepCiphertext_Throws(_backend);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [InlineData("Pkcs1")]
    [InlineData("Oaep")]
    public void Decrypt_CiphertextNotBelowTheModulus_Throws(string padding) => RSAPkcs11TestCases.Assert_Decrypt_CiphertextNotBelowTheModulus_Throws(_backend, padding);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Decrypt_OaepCiphertextFromDifferentKey_Throws() => RSAPkcs11TestCases.Assert_Decrypt_OaepCiphertextFromDifferentKey_Throws(_backend);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [InlineData("Pkcs1")]
    [InlineData("OaepSHA256")]
    public void Decrypt_CiphertextNotFromTheKey_Throws(string padding) => RSAPkcs11TestCases.Assert_Decrypt_CiphertextNotFromTheKey_Throws(_backend, padding);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ExportParameters_PublicOnly_ReturnsModulusAndExponent() => RSAPkcs11TestCases.Assert_ExportParameters_PublicOnly_ReturnsModulusAndExponent(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ExportParameters_Private_ThrowsInsecureOperation() => RSAPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecureOperation(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ImportParameters_Throws() => RSAPkcs11TestCases.Assert_ImportParameters_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignData_Pkcs1_VerifiesUnderBclFromExportedPublicKey() => RSAPkcs11TestCases.Assert_SignData_Pkcs1_VerifiesUnderBclFromExportedPublicKey(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignData_Pss_VerifiesUnderBclFromExportedPublicKey() => RSAPkcs11TestCases.Assert_SignData_Pss_VerifiesUnderBclFromExportedPublicKey(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignHash_Pss_InteropsWithSignDataAndBcl() => RSAPkcs11TestCases.Assert_SignHash_Pss_InteropsWithSignDataAndBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SignHash_Pkcs1_UnderTheDefaultPolicy_MatchesSignData() => RSAPkcs11TestCases.Assert_SignHash_Pkcs1_UnderTheDefaultPolicy_MatchesSignData(_backend);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [InlineData("SHA3-256", "Pkcs1")]
    [InlineData("SHA3-384", "Pkcs1")]
    [InlineData("SHA3-512", "Pkcs1")]
    [InlineData("SHA3-256", "Pss")]
    [InlineData("SHA3-384", "Pss")]
    [InlineData("SHA3-512", "Pss")]
    public void SignVerifyData_Sha3_RoundTrips(string hash, string padding) => RSAPkcs11TestCases.Assert_SignVerifyData_Sha3_RoundTrips(_backend, hash, padding);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [InlineData("SHA3-256", "Pkcs1")]
    [InlineData("SHA3-384", "Pkcs1")]
    [InlineData("SHA3-512", "Pkcs1")]
    [InlineData("SHA3-256", "Pss")]
    [InlineData("SHA3-384", "Pss")]
    [InlineData("SHA3-512", "Pss")]
    public void SignHash_Sha3_InteropsWithSignData(string hash, string padding) => RSAPkcs11TestCases.Assert_SignHash_Sha3_InteropsWithSignData(_backend, hash, padding);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [InlineData("SHA3-256")]
    [InlineData("SHA3-384")]
    [InlineData("SHA3-512")]
    public void EncryptDecrypt_OaepSha3_RoundTrips(string hash) => RSAPkcs11TestCases.Assert_EncryptDecrypt_OaepSha3_RoundTrips(_backend, hash);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void VerifyData_Sha3_256Pkcs1_WycheproofVectors() => RSAPkcs11TestCases.Assert_VerifyData_Sha3_256Pkcs1_WycheproofVectors(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void VerifyHash_Sha3_256Pkcs1_WycheproofVectors() => RSAPkcs11TestCases.Assert_VerifyHash_Sha3_256Pkcs1_WycheproofVectors(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void TryDecrypt_Oaep_IntoAPlaintextSizedDestination_Succeeds() => RSAPkcs11TestCases.Assert_TryDecrypt_Oaep_IntoAPlaintextSizedDestination_Succeeds(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Encrypt_OaepMessageOverTheLimit_Throws_SessionReusable() => RSAPkcs11TestCases.Assert_Encrypt_OaepMessageOverTheLimit_Throws_SessionReusable(_backend);
}
