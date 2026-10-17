using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SHA-3 signing mechanisms over SoftHSM2 — thin wrapper over <see cref="Sha3SignatureTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class Sha3SignatureTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void EcdsaSha3_256_VerifiesUnderBcl() =>
        Sha3SignatureTestCases.Assert_EcdsaSha3_256_VerifiesUnderBcl(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void RsaPssSha3_256_VerifiesUnderBcl() =>
        Sha3SignatureTestCases.Assert_RsaPssSha3_256_VerifiesUnderBcl(_backend);
}
