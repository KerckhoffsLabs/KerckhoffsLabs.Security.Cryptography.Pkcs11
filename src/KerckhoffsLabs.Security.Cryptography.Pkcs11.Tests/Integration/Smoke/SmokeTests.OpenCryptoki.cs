using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>End-to-end smoke check against opencryptoki (shares SmokeTestAssertions with SoftHSM).</summary>
[Collection("OpenCryptoki")]
public sealed class SmokeTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalFact(nameof(Available))]
    public void GetInfo_AndSlots_AreWellFormed()
        => SmokeTestAssertions.AssertLibraryInfoAndSlots_AreWellFormed(_backend);
}
