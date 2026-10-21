using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SHA-3 signing mechanisms over Craton HSM — thin wrapper over <see cref="Sha3SignatureTestCases"/>.</summary>
[Collection("CratonHsm")]
[ResetCratonHsmLogin]
public sealed class Sha3SignatureTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void EcdsaSha3_256_VerifiesUnderBcl() =>
        Sha3SignatureTestCases.Assert_EcdsaSha3_256_VerifiesUnderBcl(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void RsaPssSha3_256_VerifiesUnderBcl() =>
        Sha3SignatureTestCases.Assert_RsaPssSha3_256_VerifiesUnderBcl(_backend);
}
