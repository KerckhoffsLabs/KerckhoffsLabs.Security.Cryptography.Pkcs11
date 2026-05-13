using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

/// <summary>
/// Shared assertions for the smoke tests. Not an xUnit test class itself — concrete
/// subclasses wire up the xUnit attributes so each backend can control skip logic.
/// </summary>
internal static class SmokeTestAssertions
{
    internal static void AssertGetInfo_ReturnsNonEmptyManufacturerAndVersion(IPkcs11Backend backend)
    {
        LibraryInfo info = backend.Library.GetInfo();
        Assert.False(string.IsNullOrWhiteSpace(info.ManufacturerId));
        Assert.False(string.IsNullOrWhiteSpace(info.CryptokiVersion));
    }
}

/// <summary>
/// End-to-end smoke check against pkcs11-mock. Always runs — the mock library is
/// always present in the test output directory.
/// </summary>
[Collection("Mock")]
public sealed class SmokeTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void GetInfo_ReturnsNonEmptyManufacturerAndVersion()
        => SmokeTestAssertions.AssertGetInfo_ReturnsNonEmptyManufacturerAndVersion(_backend);
}

/// <summary>
/// End-to-end smoke check against SoftHSM2. Skipped automatically when SoftHSM2 is
/// not installed on the host (library binary not found by <see cref="SoftHsmBackendFixture"/>).
/// </summary>
[Collection("SoftHsm")]
public sealed class SmokeTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GetInfo_ReturnsNonEmptyManufacturerAndVersion()
        => SmokeTestAssertions.AssertGetInfo_ReturnsNonEmptyManufacturerAndVersion(_backend);
}
