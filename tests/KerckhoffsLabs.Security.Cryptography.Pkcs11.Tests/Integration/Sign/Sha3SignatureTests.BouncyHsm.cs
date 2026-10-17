using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SHA-3 signing mechanisms over BouncyHsm — thin wrapper over <see cref="Sha3SignatureTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class Sha3SignatureTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void EcdsaSha3_256_VerifiesUnderBcl() =>
        Sha3SignatureTestCases.Assert_EcdsaSha3_256_VerifiesUnderBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void RsaPssSha3_256_VerifiesUnderBcl() =>
        Sha3SignatureTestCases.Assert_RsaPssSha3_256_VerifiesUnderBcl(_backend);
}
