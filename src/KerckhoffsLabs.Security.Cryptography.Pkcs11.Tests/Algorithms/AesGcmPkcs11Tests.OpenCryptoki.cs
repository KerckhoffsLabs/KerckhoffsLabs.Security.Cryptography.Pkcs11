using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>AesGcmPkcs11 over OpenCryptoki — thin wrapper over <see cref="AesGcmPkcs11TestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class AesGcmPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalFact(nameof(Available))]
    public void Ctor_NonAesKey_Throws() => AesGcmPkcs11TestCases.Assert_Ctor_NonAesKey_Throws(_backend);

    [ConditionalTheory(nameof(Available))]
    [InlineData(8)]
    [InlineData(13)]
    public void Encrypt_InvalidNonceLength_Throws(int n) => AesGcmPkcs11TestCases.Assert_Encrypt_InvalidNonceLength_Throws(_backend, n);

    [ConditionalTheory(nameof(Available))]
    [InlineData(8)]
    [InlineData(13)]
    public void Decrypt_InvalidNonceLength_Throws(int n) => AesGcmPkcs11TestCases.Assert_Decrypt_InvalidNonceLength_Throws(_backend, n);

    [ConditionalTheory(nameof(Available))]
    [InlineData(8)]
    [InlineData(11)]
    [InlineData(17)]
    public void Encrypt_InvalidTagLength_Throws(int t) => AesGcmPkcs11TestCases.Assert_Encrypt_InvalidTagLength_Throws(_backend, t);

    [ConditionalTheory(nameof(Available))]
    [InlineData(8)]
    [InlineData(11)]
    [InlineData(17)]
    public void Decrypt_InvalidTagLength_Throws(int t) => AesGcmPkcs11TestCases.Assert_Decrypt_InvalidTagLength_Throws(_backend, t);

    [ConditionalFact(nameof(Available))]
    public void Encrypt_CiphertextLengthMismatch_Throws() => AesGcmPkcs11TestCases.Assert_Encrypt_CiphertextLengthMismatch_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_PlaintextLengthMismatch_Throws() => AesGcmPkcs11TestCases.Assert_Decrypt_PlaintextLengthMismatch_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Encrypt_AfterDispose_Throws() => AesGcmPkcs11TestCases.Assert_Encrypt_AfterDispose_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_AfterDispose_Throws() => AesGcmPkcs11TestCases.Assert_Decrypt_AfterDispose_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void EncryptDecrypt_RoundTrips_WithAad() => AesGcmPkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_WithAad(_backend);

    [ConditionalFact(nameof(Available))]
    public void EncryptDecrypt_RoundTrips_NoAad() => AesGcmPkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_NoAad(_backend);

    [ConditionalTheory(nameof(Available))]
    [InlineData(12)]
    [InlineData(16)]
    public void EncryptDecrypt_RoundTrips_VariousTagSizes(int tagLen) => AesGcmPkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_VariousTagSizes(_backend, tagLen);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_TamperedTag_Throws() => AesGcmPkcs11TestCases.Assert_Decrypt_TamperedTag_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_TamperedCiphertext_Throws() => AesGcmPkcs11TestCases.Assert_Decrypt_TamperedCiphertext_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_WrongAad_Throws() => AesGcmPkcs11TestCases.Assert_Decrypt_WrongAad_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_WrongNonce_Throws() => AesGcmPkcs11TestCases.Assert_Decrypt_WrongNonce_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Encrypt_KnownAnswer_MatchesReferenceVector() => AesGcmPkcs11TestCases.Assert_Encrypt_KnownAnswer_MatchesReferenceVector(_backend);
}
