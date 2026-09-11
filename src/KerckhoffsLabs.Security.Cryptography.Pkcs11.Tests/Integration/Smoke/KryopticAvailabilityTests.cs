using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// CI-health guard: makes a missing Kryoptic build fail loudly instead of silently skipping the
/// whole <c>[ConditionalFact(KryopticAvailable)]</c> suite while CI stays green — without it, a
/// build regression would erase the third-real-backend cross-check (see BL-028) unnoticed.
/// Like opencryptoki (and unlike SoftHSM, built on every leg), Kryoptic is built only where the CI
/// leg declares it via <c>PKCS11_TEST_EXPECT_KRYOPTIC=1</c> on its test step, so the guard is keyed
/// on that marker rather than on the <c>CI</c> variable.
/// </summary>
[NoBackendCollection("Reads the fixture's static File.Exists probe only — it never loads or " +
                     "initializes the module, so serializing it against the Kryoptic collection would buy nothing.")]
public sealed class KryopticAvailabilityTests
{
    [Fact]
    public void Kryoptic_IsAvailable_WhereTheCiLegExpectsIt()
    {
        bool expected = string.Equals(
            Environment.GetEnvironmentVariable("PKCS11_TEST_EXPECT_KRYOPTIC"), "1", StringComparison.Ordinal);

        // Local runs and legs without a Kryoptic build make no promise — nothing to guard.
        if (!expected) return;

        Assert.True(KryopticBackendFixture.KryopticAvailable,
            "This CI leg declares PKCS11_TEST_EXPECT_KRYOPTIC=1 but no loadable Kryoptic library " +
            "was found next to the test assembly. Refusing to let the Kryoptic integration suite " +
            "skip silently and report green.");
    }
}
