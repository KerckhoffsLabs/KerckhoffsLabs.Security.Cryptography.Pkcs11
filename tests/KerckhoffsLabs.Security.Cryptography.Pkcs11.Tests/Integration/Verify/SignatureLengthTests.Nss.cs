using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

/// <summary>SignatureLength over NSS — thin wrapper over <see cref="SignatureLengthTestCases"/>.</summary>
[Collection("Nss")]
public sealed class SignatureLengthTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void EcDsa_WrongLengthSignature_ReturnsFalse() => SignatureLengthTestCases.Assert_EcDsa_WrongLengthSignature_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Rsa_WrongLengthSignature_ReturnsFalse() => SignatureLengthTestCases.Assert_Rsa_WrongLengthSignature_ReturnsFalse(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Hmac_WrongLengthMac_ReturnsFalse() => SignatureLengthTestCases.Assert_Hmac_WrongLengthMac_ReturnsFalse(_backend);
}
