using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SHA-3 signing mechanisms over FreeHSM — thin wrapper over <see cref="Sha3SignatureTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class Sha3SignatureTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void EcdsaSha3_256_VerifiesUnderBcl() =>
        Sha3SignatureTestCases.Assert_EcdsaSha3_256_VerifiesUnderBcl(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RsaPssSha3_256_VerifiesUnderBcl() =>
        Sha3SignatureTestCases.Assert_RsaPssSha3_256_VerifiesUnderBcl(_backend);
}
