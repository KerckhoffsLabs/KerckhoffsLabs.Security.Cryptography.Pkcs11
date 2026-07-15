using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>RSAPkcs11 over NSS — thin wrapper over <see cref="RSAPkcs11TestCases"/>.</summary>
[Collection("Nss")]
public sealed class RSAPkcs11Tests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    // NSS's RSA_EncryptBlock returns CKR_DEVICE_ERROR (not CKR_BUFFER_TOO_SMALL) on a short buffer, so
    // the wrapper can't drive RSA PKCS#1 v1.5 encryption; it skips. See NssBackendFixture.
    public static bool RsaPkcs1Encrypt => NssBackendFixture.RsaPkcs1EncryptAvailable;

    [ConditionalTheory(nameof(Available))]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    [InlineData(8192)]
    [InlineData(16384)]
    public void SignVerifyData_AcrossKeySizes_RoundTrips(int modulusBits) => RSAPkcs11TestCases.Assert_SignVerifyData_AcrossKeySizes_RoundTrips(_backend, modulusBits);

    [ConditionalTheory(nameof(Available))]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void EncryptDecrypt_OaepModernHash_RoundTrips(string hash) => RSAPkcs11TestCases.Assert_EncryptDecrypt_OaepModernHash_RoundTrips(_backend, hash);

    [ConditionalFact(nameof(Available))]
    public void Ctor_NonRsaKey_Throws() => RSAPkcs11TestCases.Assert_Ctor_NonRsaKey_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignVerifyData_Pkcs1_RoundTrips() => RSAPkcs11TestCases.Assert_SignVerifyData_Pkcs1_RoundTrips(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignVerifyData_Pss_RoundTrips() => RSAPkcs11TestCases.Assert_SignVerifyData_Pss_RoundTrips(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignData_NullArguments_Throw() => RSAPkcs11TestCases.Assert_SignData_NullArguments_Throw(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignData_BadRange_Throws() => RSAPkcs11TestCases.Assert_SignData_BadRange_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void VerifyData_NullArguments_Throw() => RSAPkcs11TestCases.Assert_VerifyData_NullArguments_Throw(_backend);

    [ConditionalFact(nameof(Available))]
    public void VerifyData_BadRange_Throws() => RSAPkcs11TestCases.Assert_VerifyData_BadRange_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void TrySignData_Span_VerifyData_Span_RoundTrips() => RSAPkcs11TestCases.Assert_TrySignData_Span_VerifyData_Span_RoundTrips(_backend);

    [ConditionalFact(nameof(Available))]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => RSAPkcs11TestCases.Assert_TrySignData_DestinationTooSmall_ReturnsFalse(_backend);

    [ConditionalFact(nameof(Available))]
    public void TrySignData_NullPadding_Throws() => RSAPkcs11TestCases.Assert_TrySignData_NullPadding_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void VerifyData_Span_NullPadding_Throws() => RSAPkcs11TestCases.Assert_VerifyData_Span_NullPadding_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void EncryptDecrypt_OaepSha1_RoundTrips() => RSAPkcs11TestCases.Assert_EncryptDecrypt_OaepSha1_RoundTrips(_backend);

    [ConditionalFact(nameof(RsaPkcs1Encrypt))]
    public void EncryptDecrypt_Pkcs1_UnderAllowInsecure_RoundTrips() => RSAPkcs11TestCases.Assert_EncryptDecrypt_Pkcs1_UnderAllowInsecure_RoundTrips(_backend);

    [ConditionalFact(nameof(Available))]
    public void Encrypt_NullArguments_Throw() => RSAPkcs11TestCases.Assert_Encrypt_NullArguments_Throw(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_NullArguments_Throw() => RSAPkcs11TestCases.Assert_Decrypt_NullArguments_Throw(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_TamperedOaepCiphertext_Throws() => RSAPkcs11TestCases.Assert_Decrypt_TamperedOaepCiphertext_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_OaepCiphertextFromDifferentKey_Throws() => RSAPkcs11TestCases.Assert_Decrypt_OaepCiphertextFromDifferentKey_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void ExportParameters_PublicOnly_ReturnsModulusAndExponent() => RSAPkcs11TestCases.Assert_ExportParameters_PublicOnly_ReturnsModulusAndExponent(_backend);

    [ConditionalFact(nameof(Available))]
    public void ExportParameters_Private_ThrowsInsecureOperation() => RSAPkcs11TestCases.Assert_ExportParameters_Private_ThrowsInsecureOperation(_backend);

    [ConditionalFact(nameof(Available))]
    public void ImportParameters_Throws() => RSAPkcs11TestCases.Assert_ImportParameters_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignData_Pkcs1_VerifiesUnderBclFromExportedPublicKey() => RSAPkcs11TestCases.Assert_SignData_Pkcs1_VerifiesUnderBclFromExportedPublicKey(_backend);

    [ConditionalFact(nameof(Available))]
    public void SignData_Pss_VerifiesUnderBclFromExportedPublicKey() => RSAPkcs11TestCases.Assert_SignData_Pss_VerifiesUnderBclFromExportedPublicKey(_backend);
}
