using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>Dual-function calls over Craton HSM — thin wrapper over <see cref="DualFunctionTestCases"/>. Since 0.11.2
/// (upstream 3d5f717) its CBC-PAD dual-function decryption takes parts off the block boundary and unpads only in
/// <c>C_DecryptFinal</c>, so the decrypting side runs at odd buffer lengths too.</summary>
[Collection("CratonHsm")]
public sealed class DualFunctionTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(1)]
    [InlineData(17)]
    [InlineData(4096)]
    public void DigestEncrypt_MatchesBclDigestAndCiphertext(int bufferLength) => DualFunctionTestCases.Assert_DigestEncrypt_MatchesBclDigestAndCiphertext(_backend, bufferLength);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(48)]
    [InlineData(4096)]
    public void DecryptDigest_MatchesBclPlaintextAndDigest(int bufferLength) => DualFunctionTestCases.Assert_DecryptDigest_MatchesBclPlaintextAndDigest(_backend, bufferLength);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void DecryptDigest_APartEndingLikePadding_KeepsEveryByte() => DualFunctionTestCases.Assert_DecryptDigest_APartEndingLikePadding_KeepsEveryByte(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void DecryptVerify_APartEndingLikePadding_KeepsEveryByte() => DualFunctionTestCases.Assert_DecryptVerify_APartEndingLikePadding_KeepsEveryByte(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void DecryptDigest_BadPadding_IsEncryptedDataInvalid() => DualFunctionTestCases.Assert_DecryptDigest_BadPadding_IsEncryptedDataInvalid(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(4096)]
    public void DecryptVerify_AcceptsOnlyTheSignatureOfThePlaintext(int bufferLength) => DualFunctionTestCases.Assert_DecryptVerify_AcceptsOnlyTheSignatureOfThePlaintext(_backend, bufferLength);
}
