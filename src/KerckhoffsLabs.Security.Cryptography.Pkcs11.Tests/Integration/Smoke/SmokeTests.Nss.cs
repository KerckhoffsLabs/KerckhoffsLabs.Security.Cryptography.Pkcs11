using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>End-to-end smoke check against NSS (shares SmokeTestAssertions with SoftHSM).</summary>
[Collection("Nss")]
public sealed class SmokeTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [ConditionalFact(typeof(NssBackendFixture), nameof(NssBackendFixture.NssAvailable))]
    public void GetInfo_AndSlots_AreWellFormed()
        => SmokeTestAssertions.AssertLibraryInfoAndSlots_AreWellFormed(_backend);
}
