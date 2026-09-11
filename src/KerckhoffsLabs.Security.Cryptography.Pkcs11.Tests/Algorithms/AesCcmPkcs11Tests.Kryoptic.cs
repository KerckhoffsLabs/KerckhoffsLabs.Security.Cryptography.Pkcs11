using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>AesCcmPkcs11 over Kryoptic — thin wrapper over <see cref="AesCcmPkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class AesCcmPkcs11Tests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Ctor_NonAesKey_Throws() => AesCcmPkcs11TestCases.Assert_Ctor_NonAesKey_Throws(_backend);

    [ConditionalTheory(nameof(KryopticAvailable))]
    [InlineData(6)]
    [InlineData(14)]
    public void Encrypt_InvalidNonceLength_Throws(int n) => AesCcmPkcs11TestCases.Assert_Encrypt_InvalidNonceLength_Throws(_backend, n);

    [ConditionalTheory(nameof(KryopticAvailable))]
    [InlineData(6)]
    [InlineData(14)]
    public void Decrypt_InvalidNonceLength_Throws(int n) => AesCcmPkcs11TestCases.Assert_Decrypt_InvalidNonceLength_Throws(_backend, n);

    [ConditionalTheory(nameof(KryopticAvailable))]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(18)]
    public void Encrypt_InvalidTagLength_Throws(int t) => AesCcmPkcs11TestCases.Assert_Encrypt_InvalidTagLength_Throws(_backend, t);

    [ConditionalTheory(nameof(KryopticAvailable))]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(18)]
    public void Decrypt_InvalidTagLength_Throws(int t) => AesCcmPkcs11TestCases.Assert_Decrypt_InvalidTagLength_Throws(_backend, t);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Encrypt_CiphertextLengthMismatch_Throws() => AesCcmPkcs11TestCases.Assert_Encrypt_CiphertextLengthMismatch_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Decrypt_PlaintextLengthMismatch_Throws() => AesCcmPkcs11TestCases.Assert_Decrypt_PlaintextLengthMismatch_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Encrypt_AfterDispose_Throws() => AesCcmPkcs11TestCases.Assert_Encrypt_AfterDispose_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Decrypt_AfterDispose_Throws() => AesCcmPkcs11TestCases.Assert_Decrypt_AfterDispose_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void EncryptDecrypt_RoundTrips_WithAad() => AesCcmPkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_WithAad(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void EncryptDecrypt_RoundTrips_NoAad() => AesCcmPkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_NoAad(_backend);

    [ConditionalTheory(nameof(KryopticAvailable))]
    [InlineData(7, 16)]
    [InlineData(12, 8)]
    [InlineData(13, 4)]
    public void EncryptDecrypt_RoundTrips_VariousNonceAndTagSizes(int nonceLen, int tagLen) => AesCcmPkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_VariousNonceAndTagSizes(_backend, nonceLen, tagLen);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void EncryptDecrypt_EmptyPlaintext_RoundTrips() => AesCcmPkcs11TestCases.Assert_EncryptDecrypt_EmptyPlaintext_RoundTrips(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Decrypt_TamperedTag_Throws() => AesCcmPkcs11TestCases.Assert_Decrypt_TamperedTag_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Decrypt_TamperedCiphertext_Throws() => AesCcmPkcs11TestCases.Assert_Decrypt_TamperedCiphertext_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Decrypt_WrongAad_Throws() => AesCcmPkcs11TestCases.Assert_Decrypt_WrongAad_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Decrypt_WrongNonce_Throws() => AesCcmPkcs11TestCases.Assert_Decrypt_WrongNonce_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Encrypt_KnownAnswer_MatchesReferenceVector() => AesCcmPkcs11TestCases.Assert_Encrypt_KnownAnswer_MatchesReferenceVector(_backend);
}
