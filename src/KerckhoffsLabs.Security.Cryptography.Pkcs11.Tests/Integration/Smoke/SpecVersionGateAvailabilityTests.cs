using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// CI-health guard: makes missing pkcs11-gate shims fail loudly instead of letting the whole
/// <c>SpecVersionGateTests</c> suite skip silently while CI stays green. The gates are built by
/// the BuildPkcs11Gate target on every non-Windows CI leg, so availability is enforced there;
/// Windows gets its spec-version coverage from the hermetic <c>DelegatesLoaderTests</c>.
/// </summary>
public sealed class SpecVersionGateAvailabilityTests
{
    [Fact]
    public void Gates_AreAvailable_OnCiBuildPlatforms()
    {
        bool inCi = string.Equals(
            Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase);

        // Locally a developer may skip the native builds; on Windows the gates don't exist.
        if (!inCi || OperatingSystem.IsWindows()) return;

        Assert.True(SoftHsmGate240Fixture.Available,
            "pkcs11-gate240.so (or its SoftHSM target) is unavailable on a CI Linux/macOS leg: " +
            "the BuildPkcs11Gate target should have placed it next to the test assembly. " +
            "Refusing to let the v2.40 compatibility suite skip silently and report green.");
        Assert.True(SoftHsmGate30Fixture.Available,
            "pkcs11-gate30.so (or its SoftHSM target) is unavailable on a CI Linux/macOS leg: " +
            "the BuildPkcs11Gate target should have placed it next to the test assembly. " +
            "Refusing to let the v3.0 compatibility suite skip silently and report green.");
    }
}
