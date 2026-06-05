using System.Globalization;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// Shared assertions for the smoke tests. Not an xUnit test class itself — concrete
/// subclasses wire up the xUnit attributes so each backend can control skip logic.
/// </summary>
internal static class SmokeTestAssertions
{
    internal static void AssertLibraryInfoAndSlots_AreWellFormed(IPkcs11Backend backend)
    {
        LibraryInfo info = backend.Library.GetInfo();

        Assert.False(string.IsNullOrWhiteSpace(info.ManufacturerId));
        Assert.False(string.IsNullOrWhiteSpace(info.LibraryDescription));

        // CryptokiVersion must parse as "major.minor" with a Cryptoki-2-or-later major — a
        // version-rendering regression (e.g. a swapped/zeroed CK_VERSION byte) would slip past a
        // mere non-empty-string check but is caught here.
        Assert.Matches(@"^\d+\.\d+$", info.CryptokiVersion);
        int cryptokiMajor = int.Parse(info.CryptokiVersion.Split('.')[0], CultureInfo.InvariantCulture);
        Assert.True(cryptokiMajor >= 2,
            $"Cryptoki major version should be >= 2, was '{info.CryptokiVersion}'.");

        // LibraryVersion is likewise a "major.minor" string.
        Assert.Matches(@"^\d+\.\d+$", info.LibraryVersion);

        // The module must report at least one slot (independent of token presence).
        Assert.NotEmpty(backend.Library.GetSlotList(tokenPresent: false));
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
    public void GetInfo_AndSlots_AreWellFormed()
        => SmokeTestAssertions.AssertLibraryInfoAndSlots_AreWellFormed(_backend);
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
    public void GetInfo_AndSlots_AreWellFormed()
        => SmokeTestAssertions.AssertLibraryInfoAndSlots_AreWellFormed(_backend);
}
