using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>ChaCha20Poly1305Pkcs11 over NSS — thin wrapper over <see cref="ChaCha20Poly1305Pkcs11TestCases"/>.</summary>
[Collection("Nss")]
public sealed class ChaCha20Poly1305Pkcs11Tests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    [ConditionalFact(nameof(Available))]
    public void Ctor_NonChaChaKey_Throws() => ChaCha20Poly1305Pkcs11TestCases.Assert_Ctor_NonChaChaKey_Throws(_backend);

    [ConditionalTheory(nameof(Available))]
    [InlineData(8)]
    [InlineData(13)]
    public void Encrypt_InvalidNonceLength_Throws(int n) => ChaCha20Poly1305Pkcs11TestCases.Assert_Encrypt_InvalidNonceLength_Throws(_backend, n);

    [ConditionalTheory(nameof(Available))]
    [InlineData(8)]
    [InlineData(13)]
    public void Decrypt_InvalidNonceLength_Throws(int n) => ChaCha20Poly1305Pkcs11TestCases.Assert_Decrypt_InvalidNonceLength_Throws(_backend, n);

    [ConditionalTheory(nameof(Available))]
    [InlineData(12)]
    [InlineData(17)]
    public void Encrypt_InvalidTagLength_Throws(int t) => ChaCha20Poly1305Pkcs11TestCases.Assert_Encrypt_InvalidTagLength_Throws(_backend, t);

    [ConditionalTheory(nameof(Available))]
    [InlineData(12)]
    [InlineData(17)]
    public void Decrypt_InvalidTagLength_Throws(int t) => ChaCha20Poly1305Pkcs11TestCases.Assert_Decrypt_InvalidTagLength_Throws(_backend, t);

    [ConditionalFact(nameof(Available))]
    public void Encrypt_CiphertextLengthMismatch_Throws() => ChaCha20Poly1305Pkcs11TestCases.Assert_Encrypt_CiphertextLengthMismatch_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_PlaintextLengthMismatch_Throws() => ChaCha20Poly1305Pkcs11TestCases.Assert_Decrypt_PlaintextLengthMismatch_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Encrypt_AfterDispose_Throws() => ChaCha20Poly1305Pkcs11TestCases.Assert_Encrypt_AfterDispose_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_AfterDispose_Throws() => ChaCha20Poly1305Pkcs11TestCases.Assert_Decrypt_AfterDispose_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void EncryptDecrypt_RoundTrips_WithAad() => ChaCha20Poly1305Pkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_WithAad(_backend);

    [ConditionalFact(nameof(Available))]
    public void EncryptDecrypt_RoundTrips_NoAad() => ChaCha20Poly1305Pkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_NoAad(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_TamperedTag_Throws() => ChaCha20Poly1305Pkcs11TestCases.Assert_Decrypt_TamperedTag_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_TamperedCiphertext_Throws() => ChaCha20Poly1305Pkcs11TestCases.Assert_Decrypt_TamperedCiphertext_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_WrongAad_Throws() => ChaCha20Poly1305Pkcs11TestCases.Assert_Decrypt_WrongAad_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Decrypt_WrongNonce_Throws() => ChaCha20Poly1305Pkcs11TestCases.Assert_Decrypt_WrongNonce_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Encrypt_KnownAnswer_MatchesReferenceVector() => ChaCha20Poly1305Pkcs11TestCases.Assert_Encrypt_KnownAnswer_MatchesReferenceVector(_backend);
}
