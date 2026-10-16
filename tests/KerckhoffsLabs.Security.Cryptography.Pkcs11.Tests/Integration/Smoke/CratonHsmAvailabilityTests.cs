using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// CI-health guard: makes a missing Craton HSM build fail loudly instead of silently skipping the
/// whole <c>[Fact(SkipUnless = nameof(CratonHsmAvailable))]</c> suite while CI stays green — without it, a
/// build regression would erase the Craton HSM cross-check unnoticed.
/// Like Kryoptic (and unlike SoftHSM, built on every leg), Craton HSM is built only where the CI
/// leg declares it via <c>PKCS11_TEST_EXPECT_CRATON_HSM=1</c> on its test step, so the guard is keyed
/// on that marker rather than on the <c>CI</c> variable.
/// </summary>
[NoBackendCollection("Reads the fixture's static File.Exists probe only — it never loads or " +
                     "initializes the module, so serializing it against the CratonHsm collection would buy nothing.")]
public sealed class CratonHsmAvailabilityTests
{
    [Fact]
    public void CratonHsm_IsAvailable_WhereTheCiLegExpectsIt()
    {
        bool expected = string.Equals(
            Environment.GetEnvironmentVariable("PKCS11_TEST_EXPECT_CRATON_HSM"), "1", StringComparison.Ordinal);

        // Local runs and legs without a CratonHsm build make no promise — nothing to guard.
        if (!expected) return;

        Assert.True(CratonHsmBackendFixture.CratonHsmAvailable,
            "This CI leg declares PKCS11_TEST_EXPECT_CRATON_HSM=1 but no loadable Craton HSM library " +
            "was found next to the test assembly. Refusing to let the Craton HSM integration suite " +
            "skip silently and report green.");
    }
}
