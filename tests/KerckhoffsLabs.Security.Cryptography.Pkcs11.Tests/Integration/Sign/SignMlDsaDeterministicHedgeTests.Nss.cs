using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>SignMlDsaDeterministicHedge over NSS softoken — thin wrapper over <see cref="SignMlDsaDeterministicHedgeTestCases"/>.</summary>
[Collection("Nss")]
public sealed class SignMlDsaDeterministicHedgeTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void DeterministicHedge_ProducesIdenticalSignatures() => SignMlDsaDeterministicHedgeTestCases.Assert_DeterministicHedge_ProducesIdenticalSignatures(_backend);
}
