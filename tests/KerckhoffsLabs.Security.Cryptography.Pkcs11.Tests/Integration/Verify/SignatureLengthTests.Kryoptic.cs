using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

/// <summary>SignatureLength over Kryoptic — thin wrapper over <see cref="SignatureLengthTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class SignatureLengthTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void EcDsa_WrongLengthSignature_ReturnsFalse() => SignatureLengthTestCases.Assert_EcDsa_WrongLengthSignature_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Rsa_WrongLengthSignature_ReturnsFalse() => SignatureLengthTestCases.Assert_Rsa_WrongLengthSignature_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Hmac_WrongLengthMac_ReturnsFalse() => SignatureLengthTestCases.Assert_Hmac_WrongLengthMac_ReturnsFalse(_backend);
}
