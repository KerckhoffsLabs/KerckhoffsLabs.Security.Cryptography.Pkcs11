using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

/// <summary>SignatureLength over BouncyHsm — thin wrapper over <see cref="SignatureLengthTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class SignatureLengthTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EcDsa_WrongLengthSignature_ReturnsFalse() => SignatureLengthTestCases.Assert_EcDsa_WrongLengthSignature_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.WrongLengthRsaSignatureRejectionAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm's client refuses an empty signature with CKR_ARGUMENTS_BAD")]
    public void Rsa_WrongLengthSignature_ReturnsFalse() => SignatureLengthTestCases.Assert_Rsa_WrongLengthSignature_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Hmac_WrongLengthMac_ReturnsFalse() => SignatureLengthTestCases.Assert_Hmac_WrongLengthMac_ReturnsFalse(_backend);
}
