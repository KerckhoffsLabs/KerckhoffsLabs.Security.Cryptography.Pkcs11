using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>AesGcmPkcs11 over tpm2-pkcs11 — thin wrapper over <see cref="AesGcmPkcs11TestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class AesGcmPkcs11Tests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Ctor_NonAesKey_Throws() => AesGcmPkcs11TestCases.Assert_Ctor_NonAesKey_Throws(_backend);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    [InlineData(8)]
    [InlineData(13)]
    public void Encrypt_InvalidNonceLength_Throws(int n) => AesGcmPkcs11TestCases.Assert_Encrypt_InvalidNonceLength_Throws(_backend, n);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    [InlineData(8)]
    [InlineData(13)]
    public void Decrypt_InvalidNonceLength_Throws(int n) => AesGcmPkcs11TestCases.Assert_Decrypt_InvalidNonceLength_Throws(_backend, n);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    [InlineData(8)]
    [InlineData(11)]
    [InlineData(17)]
    public void Encrypt_InvalidTagLength_Throws(int t) => AesGcmPkcs11TestCases.Assert_Encrypt_InvalidTagLength_Throws(_backend, t);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    [InlineData(8)]
    [InlineData(11)]
    [InlineData(17)]
    public void Decrypt_InvalidTagLength_Throws(int t) => AesGcmPkcs11TestCases.Assert_Decrypt_InvalidTagLength_Throws(_backend, t);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Encrypt_CiphertextLengthMismatch_Throws() => AesGcmPkcs11TestCases.Assert_Encrypt_CiphertextLengthMismatch_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Decrypt_PlaintextLengthMismatch_Throws() => AesGcmPkcs11TestCases.Assert_Decrypt_PlaintextLengthMismatch_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Encrypt_AfterDispose_Throws() => AesGcmPkcs11TestCases.Assert_Encrypt_AfterDispose_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Decrypt_AfterDispose_Throws() => AesGcmPkcs11TestCases.Assert_Decrypt_AfterDispose_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void EncryptDecrypt_RoundTrips_WithAad() => AesGcmPkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_WithAad(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void EncryptDecrypt_RoundTrips_NoAad() => AesGcmPkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_NoAad(_backend);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    [InlineData(12)]
    [InlineData(16)]
    public void EncryptDecrypt_RoundTrips_VariousTagSizes(int tagLen) => AesGcmPkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_VariousTagSizes(_backend, tagLen);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Decrypt_TamperedTag_Throws() => AesGcmPkcs11TestCases.Assert_Decrypt_TamperedTag_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Decrypt_TamperedCiphertext_Throws() => AesGcmPkcs11TestCases.Assert_Decrypt_TamperedCiphertext_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Decrypt_WrongAad_Throws() => AesGcmPkcs11TestCases.Assert_Decrypt_WrongAad_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Decrypt_WrongNonce_Throws() => AesGcmPkcs11TestCases.Assert_Decrypt_WrongNonce_Throws(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Encrypt_KnownAnswer_MatchesReferenceVector() => AesGcmPkcs11TestCases.Assert_Encrypt_KnownAnswer_MatchesReferenceVector(_backend);

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    [InlineData(12)]
    [InlineData(13)]
    [InlineData(14)]
    [InlineData(15)]
    [InlineData(16)]
    public void Encrypt_TagSize_MatchesBcl(int tagLen) => AesGcmPkcs11TestCases.Assert_Encrypt_TagSize_MatchesBcl(_backend, tagLen);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void EncryptDecrypt_LargeAad_MatchesBcl() => AesGcmPkcs11TestCases.Assert_EncryptDecrypt_LargeAad_MatchesBcl(_backend);
}
