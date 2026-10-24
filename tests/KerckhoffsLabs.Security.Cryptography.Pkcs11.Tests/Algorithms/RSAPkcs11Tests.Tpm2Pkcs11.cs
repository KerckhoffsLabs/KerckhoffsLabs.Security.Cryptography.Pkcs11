using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>RSAPkcs11 over tpm2-pkcs11 — thin wrapper over <see cref="RSAPkcs11TestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class RSAPkcs11Tests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    [InlineData(8192)]
    [InlineData(16384)]
    public void SignVerifyData_AcrossKeySizes_RoundTrips(int modulusBits) => RSAPkcs11TestCases.Assert_SignVerifyData_AcrossKeySizes_RoundTrips(_backend, modulusBits);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.RsaEncryptionAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 C_Encrypt answers a short buffer with CKR_GENERAL_ERROR, not CKR_BUFFER_TOO_SMALL")]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void EncryptDecrypt_OaepModernHash_RoundTrips(string hash) => RSAPkcs11TestCases.Assert_EncryptDecrypt_OaepModernHash_RoundTrips(_backend, hash);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-software/tpm2-pkcs11#564: C_GenerateKey is not implemented")]
    public void Ctor_NonRsaKey_Throws() => RSAPkcs11TestCases.Assert_Ctor_NonRsaKey_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignVerifyData_Pkcs1_RoundTrips() => RSAPkcs11TestCases.Assert_SignVerifyData_Pkcs1_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignVerifyData_Pss_RoundTrips() => RSAPkcs11TestCases.Assert_SignVerifyData_Pss_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignVerifyData_Sha224Pkcs1_UnderAllowInsecure_RoundTrips() => RSAPkcs11TestCases.Assert_SignVerifyData_Sha224Pkcs1_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignData_Sha224Pkcs1_WithoutAllowInsecure_Throws() => RSAPkcs11TestCases.Assert_SignData_Sha224Pkcs1_WithoutAllowInsecure_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignVerifyData_Sha224Pss_UnderAllowInsecure_RoundTrips() => RSAPkcs11TestCases.Assert_SignVerifyData_Sha224Pss_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignData_Sha224Pss_WithoutAllowInsecure_Throws() => RSAPkcs11TestCases.Assert_SignData_Sha224Pss_WithoutAllowInsecure_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignData_NullArguments_Throw() => RSAPkcs11TestCases.Assert_SignData_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignData_BadRange_Throws() => RSAPkcs11TestCases.Assert_SignData_BadRange_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void VerifyData_NullArguments_Throw() => RSAPkcs11TestCases.Assert_VerifyData_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void VerifyData_BadRange_Throws() => RSAPkcs11TestCases.Assert_VerifyData_BadRange_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void TrySignData_Span_VerifyData_Span_RoundTrips() => RSAPkcs11TestCases.Assert_TrySignData_Span_VerifyData_Span_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => RSAPkcs11TestCases.Assert_TrySignData_DestinationTooSmall_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void TrySignData_NullPadding_Throws() => RSAPkcs11TestCases.Assert_TrySignData_NullPadding_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void VerifyData_Span_NullPadding_Throws() => RSAPkcs11TestCases.Assert_VerifyData_Span_NullPadding_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.RsaEncryptionAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 C_Encrypt answers a short buffer with CKR_GENERAL_ERROR, not CKR_BUFFER_TOO_SMALL")]
    public void EncryptDecrypt_OaepSha1_RoundTrips() => RSAPkcs11TestCases.Assert_EncryptDecrypt_OaepSha1_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void EncryptDecrypt_OaepSha224_UnderAllowInsecure_RoundTrips() => RSAPkcs11TestCases.Assert_EncryptDecrypt_OaepSha224_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Encrypt_OaepSha224_WithoutAllowInsecure_Throws() => RSAPkcs11TestCases.Assert_Encrypt_OaepSha224_WithoutAllowInsecure_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.RsaEncryptionAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 C_Encrypt answers a short buffer with CKR_GENERAL_ERROR, not CKR_BUFFER_TOO_SMALL")]
    public void EncryptDecrypt_Pkcs1_UnderAllowInsecure_RoundTrips() => RSAPkcs11TestCases.Assert_EncryptDecrypt_Pkcs1_UnderAllowInsecure_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Encrypt_NullArguments_Throw() => RSAPkcs11TestCases.Assert_Encrypt_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Decrypt_NullArguments_Throw() => RSAPkcs11TestCases.Assert_Decrypt_NullArguments_Throw(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.RsaEncryptionAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 C_Encrypt answers a short buffer with CKR_GENERAL_ERROR, not CKR_BUFFER_TOO_SMALL")]
    public void Decrypt_TamperedOaepCiphertext_Throws() => RSAPkcs11TestCases.Assert_Decrypt_TamperedOaepCiphertext_Throws(_backend);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.FailedDecryptEndsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 leaves a refused C_Decrypt active (CKR_OPERATION_ACTIVE next)")]
    [InlineData("Pkcs1")]
    [InlineData("Oaep")]
    public void Decrypt_CiphertextNotBelowTheModulus_Throws(string padding) => RSAPkcs11TestCases.Assert_Decrypt_CiphertextNotBelowTheModulus_Throws(_backend, padding);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.RsaEncryptionAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "tpm2-pkcs11 C_Encrypt answers a short buffer with CKR_GENERAL_ERROR, not CKR_BUFFER_TOO_SMALL")]
    public void Decrypt_OaepCiphertextFromDifferentKey_Throws() => RSAPkcs11TestCases.Assert_Decrypt_OaepCiphertextFromDifferentKey_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ExportParameters_PublicOnly_ReturnsModulusAndExponent() => RSAPkcs11TestCases.Assert_ExportParameters_PublicOnly_ReturnsModulusAndExponent(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ExportParameters_Private_ThrowsInsecureOperation() => RSAPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecureOperation(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ImportParameters_Throws() => RSAPkcs11TestCases.Assert_ImportParameters_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignData_Pkcs1_VerifiesUnderBclFromExportedPublicKey() => RSAPkcs11TestCases.Assert_SignData_Pkcs1_VerifiesUnderBclFromExportedPublicKey(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignData_Pss_VerifiesUnderBclFromExportedPublicKey() => RSAPkcs11TestCases.Assert_SignData_Pss_VerifiesUnderBclFromExportedPublicKey(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignHash_Pss_InteropsWithSignDataAndBcl() => RSAPkcs11TestCases.Assert_SignHash_Pss_InteropsWithSignDataAndBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void SignHash_Pkcs1_UnderTheDefaultPolicy_MatchesSignData() => RSAPkcs11TestCases.Assert_SignHash_Pkcs1_UnderTheDefaultPolicy_MatchesSignData(_backend);
}
