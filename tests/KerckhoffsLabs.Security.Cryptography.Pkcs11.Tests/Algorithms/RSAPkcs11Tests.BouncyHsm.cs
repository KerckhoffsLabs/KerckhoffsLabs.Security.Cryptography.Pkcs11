using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>RSAPkcs11 over BouncyHsm — thin wrapper over <see cref="RSAPkcs11TestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class RSAPkcs11Tests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    public void SignVerifyData_AcrossKeySizes_RoundTrips(int modulusBits) => RSAPkcs11TestCases.Assert_SignVerifyData_AcrossKeySizes_RoundTrips(_backend, modulusBits);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void EncryptDecrypt_OaepModernHash_RoundTrips(string hash) => RSAPkcs11TestCases.Assert_EncryptDecrypt_OaepModernHash_RoundTrips(_backend, hash);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Ctor_NonRsaKey_Throws() => RSAPkcs11TestCases.Assert_Ctor_NonRsaKey_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SignVerifyData_Pkcs1_RoundTrips() => RSAPkcs11TestCases.Assert_SignVerifyData_Pkcs1_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.OutOfRangeSignatureRejectionAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "harrison314/BouncyHsm#116: a tampered PSS signature can give CKR_GENERAL_ERROR")]
    public void SignVerifyData_Pss_RoundTrips() => RSAPkcs11TestCases.Assert_SignVerifyData_Pss_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SignData_NullArguments_Throw() => RSAPkcs11TestCases.Assert_SignData_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SignData_BadRange_Throws() => RSAPkcs11TestCases.Assert_SignData_BadRange_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void VerifyData_NullArguments_Throw() => RSAPkcs11TestCases.Assert_VerifyData_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void VerifyData_BadRange_Throws() => RSAPkcs11TestCases.Assert_VerifyData_BadRange_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void TrySignData_Span_VerifyData_Span_RoundTrips() => RSAPkcs11TestCases.Assert_TrySignData_Span_VerifyData_Span_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => RSAPkcs11TestCases.Assert_TrySignData_DestinationTooSmall_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void TrySignData_NullPadding_Throws() => RSAPkcs11TestCases.Assert_TrySignData_NullPadding_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void VerifyData_Span_NullPadding_Throws() => RSAPkcs11TestCases.Assert_VerifyData_Span_NullPadding_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EncryptDecrypt_OaepSha1_RoundTrips() => RSAPkcs11TestCases.Assert_EncryptDecrypt_OaepSha1_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EncryptDecrypt_Pkcs1_UnderAllowInsecure_RoundTrips() => RSAPkcs11TestCases.Assert_EncryptDecrypt_Pkcs1_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Encrypt_NullArguments_Throw() => RSAPkcs11TestCases.Assert_Encrypt_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Decrypt_NullArguments_Throw() => RSAPkcs11TestCases.Assert_Decrypt_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Decrypt_TamperedOaepCiphertext_Throws() => RSAPkcs11TestCases.Assert_Decrypt_TamperedOaepCiphertext_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Decrypt_OaepCiphertextFromDifferentKey_Throws() => RSAPkcs11TestCases.Assert_Decrypt_OaepCiphertextFromDifferentKey_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ExportParameters_PublicOnly_ReturnsModulusAndExponent() => RSAPkcs11TestCases.Assert_ExportParameters_PublicOnly_ReturnsModulusAndExponent(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ExportParameters_Private_ThrowsInsecureOperation() => RSAPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecureOperation(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ImportParameters_Throws() => RSAPkcs11TestCases.Assert_ImportParameters_Throws(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SignData_Pkcs1_VerifiesUnderBclFromExportedPublicKey() => RSAPkcs11TestCases.Assert_SignData_Pkcs1_VerifiesUnderBclFromExportedPublicKey(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SignData_Pss_VerifiesUnderBclFromExportedPublicKey() => RSAPkcs11TestCases.Assert_SignData_Pss_VerifiesUnderBclFromExportedPublicKey(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SignHash_Pss_InteropsWithSignDataAndBcl() => RSAPkcs11TestCases.Assert_SignHash_Pss_InteropsWithSignDataAndBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SignHash_Pkcs1_UnderTheDefaultPolicy_MatchesSignData() => RSAPkcs11TestCases.Assert_SignHash_Pkcs1_UnderTheDefaultPolicy_MatchesSignData(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData("SHA3-256", "Pkcs1")]
    [InlineData("SHA3-384", "Pkcs1")]
    [InlineData("SHA3-512", "Pkcs1")]
    [InlineData("SHA3-256", "Pss")]
    [InlineData("SHA3-384", "Pss")]
    [InlineData("SHA3-512", "Pss")]
    public void SignVerifyData_Sha3_RoundTrips(string hash, string padding) => RSAPkcs11TestCases.Assert_SignVerifyData_Sha3_RoundTrips(_backend, hash, padding);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData("SHA3-256", "Pkcs1")]
    [InlineData("SHA3-384", "Pkcs1")]
    [InlineData("SHA3-512", "Pkcs1")]
    [InlineData("SHA3-256", "Pss")]
    [InlineData("SHA3-384", "Pss")]
    [InlineData("SHA3-512", "Pss")]
    public void SignHash_Sha3_InteropsWithSignData(string hash, string padding) => RSAPkcs11TestCases.Assert_SignHash_Sha3_InteropsWithSignData(_backend, hash, padding);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [InlineData("SHA3-256")]
    [InlineData("SHA3-384")]
    [InlineData("SHA3-512")]
    public void EncryptDecrypt_OaepSha3_RoundTrips(string hash) => RSAPkcs11TestCases.Assert_EncryptDecrypt_OaepSha3_RoundTrips(_backend, hash);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void VerifyData_Sha3_256Pkcs1_WycheproofVectors() => RSAPkcs11TestCases.Assert_VerifyData_Sha3_256Pkcs1_WycheproofVectors(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void VerifyHash_Sha3_256Pkcs1_WycheproofVectors() => RSAPkcs11TestCases.Assert_VerifyHash_Sha3_256Pkcs1_WycheproofVectors(_backend);
}
