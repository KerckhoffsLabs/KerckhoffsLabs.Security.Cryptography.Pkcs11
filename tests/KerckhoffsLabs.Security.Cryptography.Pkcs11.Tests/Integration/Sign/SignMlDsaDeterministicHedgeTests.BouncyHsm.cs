using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignMlDsaDeterministicHedge over BouncyHsm — thin wrapper over <see cref="SignMlDsaDeterministicHedgeTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class SignMlDsaDeterministicHedgeTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void DeterministicHedge_ProducesIdenticalSignatures() => SignMlDsaDeterministicHedgeTestCases.Assert_DeterministicHedge_ProducesIdenticalSignatures(_backend);
}
