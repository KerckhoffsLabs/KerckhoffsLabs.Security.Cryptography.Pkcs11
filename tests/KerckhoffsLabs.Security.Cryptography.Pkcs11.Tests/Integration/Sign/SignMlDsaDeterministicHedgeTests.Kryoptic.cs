using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignMlDsaDeterministicHedge over Kryoptic — thin wrapper over <see cref="SignMlDsaDeterministicHedgeTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class SignMlDsaDeterministicHedgeTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void DeterministicHedge_ProducesIdenticalSignatures() => SignMlDsaDeterministicHedgeTestCases.Assert_DeterministicHedge_ProducesIdenticalSignatures(_backend);
}
