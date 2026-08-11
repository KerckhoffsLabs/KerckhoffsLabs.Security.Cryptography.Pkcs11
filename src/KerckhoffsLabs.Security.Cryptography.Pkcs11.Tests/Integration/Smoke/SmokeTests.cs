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

        // A swapped or zeroed CK_VERSION byte would slip past a mere non-null check but is caught
        // here: every module this suite loads is Cryptoki 2 or later.
        Assert.True(info.CryptokiVersion >= new Version(2, 0),
            $"Cryptoki version should be >= 2.0, was '{info.CryptokiVersion}'.");
        Assert.True(backend.Library.SupportsCryptokiVersion(2, 0));

        // The vendor's own library version is independent of the spec version, but is equally
        // required to be present rather than a default-constructed 0.0.
        Assert.NotEqual(new Version(0, 0), info.LibraryVersion);

        // The module must report at least one slot (independent of token presence).
        Assert.NotEmpty(backend.Library.GetSlotList(tokenPresent: false));
    }
}
