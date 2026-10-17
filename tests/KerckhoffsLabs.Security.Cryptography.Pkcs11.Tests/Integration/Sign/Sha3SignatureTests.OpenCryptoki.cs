using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SHA-3 signing mechanisms over opencryptoki — thin wrapper over <see cref="Sha3SignatureTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class Sha3SignatureTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void EcdsaSha3_256_VerifiesUnderBcl() =>
        Sha3SignatureTestCases.Assert_EcdsaSha3_256_VerifiesUnderBcl(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void RsaPssSha3_256_VerifiesUnderBcl() =>
        Sha3SignatureTestCases.Assert_RsaPssSha3_256_VerifiesUnderBcl(_backend);
}
