using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel;

/// <summary>
/// End-to-end smoke check that the library loads a backend and completes a
/// minimal Cryptoki lifecycle. Runs against pkcs11-mock; SoftHSM2 gets its
/// own smoke variant in T4.
/// </summary>
public abstract class SmokeTests
{
    private readonly IPkcs11Backend _backend;
    protected SmokeTests(IPkcs11Backend backend) { _backend = backend; }

    [Fact]
    public void GetInfo_ReturnsNonEmptyManufacturerAndVersion()
    {
        LibraryInfo info = _backend.Library.GetInfo();
        Assert.False(string.IsNullOrWhiteSpace(info.ManufacturerId));
        Assert.False(string.IsNullOrWhiteSpace(info.CryptokiVersion));
    }
}

[Collection("Mock")]
public sealed class SmokeTests_Mock : SmokeTests { public SmokeTests_Mock(MockBackendFixture f) : base(f) { } }
