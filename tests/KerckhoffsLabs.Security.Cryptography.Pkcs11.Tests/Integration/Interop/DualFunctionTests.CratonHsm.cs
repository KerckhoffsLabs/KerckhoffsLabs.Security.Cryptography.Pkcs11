using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>Dual-function calls over Craton HSM — thin wrapper over <see cref="DualFunctionTestCases"/>.</summary>
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
    [InlineData(16)]
    [InlineData(48)]
    [InlineData(4096)]
    public void DecryptDigest_MatchesBclPlaintextAndDigest(int bufferLength) => DualFunctionTestCases.Assert_DecryptDigest_MatchesBclPlaintextAndDigest(_backend, bufferLength);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CbcPadDualDecryptAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Craton HSM unpads every CBC-PAD part of a dual-function decryption")]
    public void DecryptDigest_APartEndingLikePadding_KeepsEveryByte() => DualFunctionTestCases.Assert_DecryptDigest_APartEndingLikePadding_KeepsEveryByte(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [InlineData(16)]
    [InlineData(4096)]
    public void DecryptVerify_AcceptsOnlyTheSignatureOfThePlaintext(int bufferLength) => DualFunctionTestCases.Assert_DecryptVerify_AcceptsOnlyTheSignatureOfThePlaintext(_backend, bufferLength);
}
