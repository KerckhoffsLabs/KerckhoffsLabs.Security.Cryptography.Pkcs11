using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignMlDsaDeterministicHedge over FreeHSM — thin wrapper over <see cref="SignMlDsaDeterministicHedgeTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class SignMlDsaDeterministicHedgeTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void DeterministicHedge_ProducesIdenticalSignatures() => SignMlDsaDeterministicHedgeTestCases.Assert_DeterministicHedge_ProducesIdenticalSignatures(_backend);
}
