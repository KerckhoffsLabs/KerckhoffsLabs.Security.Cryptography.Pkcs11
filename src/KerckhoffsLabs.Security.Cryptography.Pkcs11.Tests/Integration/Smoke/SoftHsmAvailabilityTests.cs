using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// CI-health guard: makes a missing SoftHSM2 fail loudly instead of silently skipping the
/// whole <c>[ConditionalFact(SoftHsmAvailable)]</c> integration suite while CI stays green.
/// SoftHSM is built from the vendored submodule on Linux only; on Windows and macOS it is
/// intentionally absent (the fixture does not auto-discover a system install), so the guard
/// is scoped to CI runs on Linux.
/// </summary>
public sealed class SoftHsmAvailabilityTests
{
    [Fact]
    public void SoftHsm_IsAvailable_OnCiBuildPlatforms()
    {
        bool inCi = string.Equals(
            Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase);

        // Only enforced in CI on Linux, the one platform where the vendored SoftHSM is built.
        // Locally a developer may skip the native build (SkipSoftHsmV2Build); Windows and macOS
        // never build it.
        if (!inCi || !OperatingSystem.IsLinux()) return;

        Assert.True(SoftHsmBackendFixture.SoftHsmAvailable,
            "SoftHSM2 is unavailable on a CI build platform (Linux/macOS): the vendored " +
            "BuildSoftHsmV2 target should have placed libsofthsm2 next to the test assembly. " +
            "Refusing to let the SoftHSM integration suite skip silently and report green.");
    }
}
