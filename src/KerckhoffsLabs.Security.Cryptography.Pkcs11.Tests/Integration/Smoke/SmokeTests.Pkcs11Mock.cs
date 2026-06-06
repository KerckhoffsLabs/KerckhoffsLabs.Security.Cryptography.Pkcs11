using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// End-to-end smoke check against pkcs11-mock. Always runs — the mock library is
/// always present in the test output directory.
/// </summary>
[Collection("Mock")]
public sealed class SmokeTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void GetInfo_AndSlots_AreWellFormed()
        => SmokeTestAssertions.AssertLibraryInfoAndSlots_AreWellFormed(_backend);
}
