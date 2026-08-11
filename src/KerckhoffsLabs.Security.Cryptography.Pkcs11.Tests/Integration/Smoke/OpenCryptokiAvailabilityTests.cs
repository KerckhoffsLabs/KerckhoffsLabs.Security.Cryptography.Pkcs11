using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// CI-health guard: makes a missing opencryptoki fail loudly instead of silently skipping the
/// whole <c>[ConditionalFact(OpenCryptokiAvailable)]</c> suite while CI stays green — without
/// it, a provisioning regression would erase the second-real-backend cross-check unnoticed.
/// Unlike SoftHSM (built on every leg), opencryptoki is provisioned only where the CI leg
/// declares it via <c>PKCS11_TEST_EXPECT_OPENCRYPTOKI=1</c> on its test step, so the guard is
/// keyed on that marker rather than on the <c>CI</c> variable.
/// </summary>
[NoBackendCollection("Reads the fixture's static File.Exists probe only — it never loads or " +
                     "initializes the module, so serializing it against the OpenCryptoki collection would buy nothing.")]
public sealed class OpenCryptokiAvailabilityTests
{
    [Fact]
    public void OpenCryptoki_IsAvailable_WhereTheCiLegExpectsIt()
    {
        bool expected = string.Equals(
            Environment.GetEnvironmentVariable("PKCS11_TEST_EXPECT_OPENCRYPTOKI"), "1", StringComparison.Ordinal);

        // Local runs and legs without opencryptoki provisioning make no promise — nothing to guard.
        if (!expected) return;

        Assert.True(OpenCryptokiBackendFixture.OpenCryptokiAvailable,
            "This CI leg declares PKCS11_TEST_EXPECT_OPENCRYPTOKI=1 but no loadable opencryptoki " +
            "library is configured (PKCS11_TEST_OPENCRYPTOKI_LIBRARY unset or pointing at a missing " +
            "file). Refusing to let the opencryptoki integration suite skip silently and report green.");
    }
}
