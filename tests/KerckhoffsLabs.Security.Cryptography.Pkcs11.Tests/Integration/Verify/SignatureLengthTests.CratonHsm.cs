using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

/// <summary>SignatureLength over Craton HSM — thin wrapper over <see cref="SignatureLengthTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class SignatureLengthTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EcDsa_WrongLengthSignature_ReturnsFalse() => SignatureLengthTestCases.Assert_EcDsa_WrongLengthSignature_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Rsa_WrongLengthSignature_ReturnsFalse() => SignatureLengthTestCases.Assert_Rsa_WrongLengthSignature_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Hmac_WrongLengthMac_ReturnsFalse() => SignatureLengthTestCases.Assert_Hmac_WrongLengthMac_ReturnsFalse(_backend);
}
