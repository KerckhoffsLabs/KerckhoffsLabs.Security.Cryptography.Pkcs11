using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

/// <summary>SignatureLength over SoftHsm — thin wrapper over <see cref="SignatureLengthTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class SignatureLengthTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void EcDsa_WrongLengthSignature_ReturnsFalse() => SignatureLengthTestCases.Assert_EcDsa_WrongLengthSignature_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Rsa_WrongLengthSignature_ReturnsFalse() => SignatureLengthTestCases.Assert_Rsa_WrongLengthSignature_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Hmac_WrongLengthMac_ReturnsFalse() => SignatureLengthTestCases.Assert_Hmac_WrongLengthMac_ReturnsFalse(_backend);
}
