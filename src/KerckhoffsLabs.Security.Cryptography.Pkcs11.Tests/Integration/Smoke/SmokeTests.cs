using System.Globalization;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// Shared assertions for the smoke tests. Not an xUnit test class itself — the concrete per-backend
/// subclasses (<c>SmokeTests.Pkcs11Mock.cs</c>, <c>SmokeTests.SoftHsm2.cs</c>) wire up the xUnit
/// attributes so each backend can control skip logic.
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
