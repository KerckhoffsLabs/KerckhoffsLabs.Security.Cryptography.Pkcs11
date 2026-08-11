using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// CI-health guard: makes a missing SoftHSM2 fail loudly instead of silently skipping the
/// whole <c>[ConditionalFact(SoftHsmAvailable)]</c> integration suite while CI stays green.
/// SoftHSM is built from the vendored submodule on every CI leg (Linux, macOS, Windows x64+x86,
/// each for its own architecture), so the guard enforces availability on all of them.
/// </summary>
[NoBackendCollection("Reads the fixture's static File.Exists probe only — it never loads or " +
                     "initializes the module, so serializing it against the SoftHsm collection would buy nothing.")]
public sealed class SoftHsmAvailabilityTests
{
    [Fact]
    public void SoftHsm_IsAvailable_OnCiBuildPlatforms()
    {
        bool inCi = string.Equals(
            Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase);

        // Enforced on every CI leg — all build the vendored SoftHSM for their own architecture.
        // Locally a developer may skip the native build (SkipSoftHsmV2Build).
        if (!inCi) return;

        Assert.True(SoftHsmBackendFixture.SoftHsmAvailable,
            "SoftHSM2 is unavailable on a CI build platform (Linux/macOS): the vendored " +
            "BuildSoftHsmV2 target should have placed libsofthsm2 next to the test assembly. " +
            "Refusing to let the SoftHSM integration suite skip silently and report green.");
    }
}
