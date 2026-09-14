using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// End-to-end smoke check against SoftHSM2. Skipped automatically when SoftHSM2 is
/// not installed on the host (library binary not found by <see cref="SoftHsmBackendFixture"/>).
/// </summary>
[Collection("SoftHsm")]
public sealed class SmokeTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;


    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void GetInfo_AndSlots_AreWellFormed()
        => SmokeTestAssertions.AssertLibraryInfoAndSlots_AreWellFormed(_backend);
}
