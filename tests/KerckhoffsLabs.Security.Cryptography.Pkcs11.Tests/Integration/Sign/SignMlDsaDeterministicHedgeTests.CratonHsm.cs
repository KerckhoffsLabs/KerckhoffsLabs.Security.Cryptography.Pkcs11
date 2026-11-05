using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignMlDsaDeterministicHedge over Craton HSM — thin wrapper over <see cref="SignMlDsaDeterministicHedgeTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class SignMlDsaDeterministicHedgeTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void DeterministicHedge_ProducesIdenticalSignatures() => SignMlDsaDeterministicHedgeTestCases.Assert_DeterministicHedge_ProducesIdenticalSignatures(_backend);
}
