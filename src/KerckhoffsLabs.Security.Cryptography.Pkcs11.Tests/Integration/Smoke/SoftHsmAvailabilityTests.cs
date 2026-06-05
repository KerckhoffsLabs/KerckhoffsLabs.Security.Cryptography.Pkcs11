using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// CI-health guard: makes a missing SoftHSM2 fail loudly instead of silently skipping the
/// whole <c>[ConditionalFact(SoftHsmAvailable)]</c> integration suite while CI stays green.
/// SoftHSM is built from the vendored submodule on Linux, macOS, and Windows-x64; only the
/// Windows-x86 leg runs pkcs11-mock only (an x86 testhost can't load the x64 library), so the
/// guard is scoped to the build platforms.
/// </summary>
public sealed class SoftHsmAvailabilityTests
{
    [Fact]
    public void SoftHsm_IsAvailable_OnCiBuildPlatforms()
    {
        bool inCi = string.Equals(
            Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase);

        // Enforced in CI on every platform where the vendored SoftHSM is built: Linux, macOS, and
        // Windows-x64. Only the Windows-x86 leg is exempt — it can't load the x64 library the build
        // produces. Locally a developer may skip the native build (SkipSoftHsmV2Build).
        if (!inCi) return;
        if (OperatingSystem.IsWindows() && RuntimeInformation.ProcessArchitecture == Architecture.X86) return;

        Assert.True(SoftHsmBackendFixture.SoftHsmAvailable,
            "SoftHSM2 is unavailable on a CI build platform (Linux/macOS): the vendored " +
            "BuildSoftHsmV2 target should have placed libsofthsm2 next to the test assembly. " +
            "Refusing to let the SoftHSM integration suite skip silently and report green.");
    }
}
