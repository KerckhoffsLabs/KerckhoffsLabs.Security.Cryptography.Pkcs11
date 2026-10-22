using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>AesCcmPkcs11 over Craton HSM — thin wrapper over <see cref="AesCcmPkcs11TestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class AesCcmPkcs11Tests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Ctor_NonAesKey_Throws() => AesCcmPkcs11TestCases.Assert_Ctor_NonAesKey_Throws(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(6)]
    [InlineData(14)]
    public void Encrypt_InvalidNonceLength_Throws(int n) => AesCcmPkcs11TestCases.Assert_Encrypt_InvalidNonceLength_Throws(_backend, n);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(6)]
    [InlineData(14)]
    public void Decrypt_InvalidNonceLength_Throws(int n) => AesCcmPkcs11TestCases.Assert_Decrypt_InvalidNonceLength_Throws(_backend, n);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(18)]
    public void Encrypt_InvalidTagLength_Throws(int t) => AesCcmPkcs11TestCases.Assert_Encrypt_InvalidTagLength_Throws(_backend, t);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(18)]
    public void Decrypt_InvalidTagLength_Throws(int t) => AesCcmPkcs11TestCases.Assert_Decrypt_InvalidTagLength_Throws(_backend, t);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Encrypt_CiphertextLengthMismatch_Throws() => AesCcmPkcs11TestCases.Assert_Encrypt_CiphertextLengthMismatch_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Decrypt_PlaintextLengthMismatch_Throws() => AesCcmPkcs11TestCases.Assert_Decrypt_PlaintextLengthMismatch_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Encrypt_AfterDispose_Throws() => AesCcmPkcs11TestCases.Assert_Encrypt_AfterDispose_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Decrypt_AfterDispose_Throws() => AesCcmPkcs11TestCases.Assert_Decrypt_AfterDispose_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EncryptDecrypt_RoundTrips_WithAad() => AesCcmPkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_WithAad(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EncryptDecrypt_RoundTrips_NoAad() => AesCcmPkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_NoAad(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(7, 16)]
    [InlineData(12, 8)]
    [InlineData(13, 4)]
    public void EncryptDecrypt_RoundTrips_VariousNonceAndTagSizes(int nonceLen, int tagLen) => AesCcmPkcs11TestCases.Assert_EncryptDecrypt_RoundTrips_VariousNonceAndTagSizes(_backend, nonceLen, tagLen);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EncryptDecrypt_EmptyPlaintext_RoundTrips() => AesCcmPkcs11TestCases.Assert_EncryptDecrypt_EmptyPlaintext_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Decrypt_TamperedTag_Throws() => AesCcmPkcs11TestCases.Assert_Decrypt_TamperedTag_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Decrypt_TamperedCiphertext_Throws() => AesCcmPkcs11TestCases.Assert_Decrypt_TamperedCiphertext_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Decrypt_WrongAad_Throws() => AesCcmPkcs11TestCases.Assert_Decrypt_WrongAad_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Decrypt_WrongNonce_Throws() => AesCcmPkcs11TestCases.Assert_Decrypt_WrongNonce_Throws(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Encrypt_KnownAnswer_MatchesReferenceVector() => AesCcmPkcs11TestCases.Assert_Encrypt_KnownAnswer_MatchesReferenceVector(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(8)]
    [InlineData(10)]
    [InlineData(12)]
    [InlineData(14)]
    [InlineData(16)]
    public void Encrypt_EveryNonceLength_MatchesBcl(int tagLen) => AesCcmPkcs11TestCases.Assert_Encrypt_EveryNonceLength_MatchesBcl(_backend, tagLen);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EncryptDecrypt_LargeAad_MatchesBcl() => AesCcmPkcs11TestCases.Assert_EncryptDecrypt_LargeAad_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void FixedTagSize_TagOfAnotherLegalSize_Throws() => AesCcmPkcs11TestCases.Assert_FixedTagSize_TagOfAnotherLegalSize_Throws(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(2)]
    [InlineData(5)]
    [InlineData(18)]
    public void PerCallTagSize_IllegalTagLength_Throws(int t) => AesCcmPkcs11TestCases.Assert_PerCallTagSize_IllegalTagLength_Throws(_backend, t);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(4)]
    [InlineData(8)]
    [InlineData(12)]
    [InlineData(14)]
    [InlineData(16)]
    public void PerCallTagSize_MatchesBcl_AndRoundTrips(int t) => AesCcmPkcs11TestCases.Assert_PerCallTagSize_MatchesBcl_AndRoundTrips(_backend, t);
}
