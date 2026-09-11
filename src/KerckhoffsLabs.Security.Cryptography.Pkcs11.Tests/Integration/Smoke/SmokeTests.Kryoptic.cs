using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>End-to-end smoke check against Kryoptic (shares SmokeTestAssertions with SoftHSM/opencryptoki).</summary>
[Collection("Kryoptic")]
public sealed class SmokeTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;
    public static bool Available => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(Available))]
    public void GetInfo_AndSlots_AreWellFormed()
        => SmokeTestAssertions.AssertLibraryInfoAndSlots_AreWellFormed(_backend, expectNonZeroLibraryVersion: false);
}
