using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// CI-health guard: makes a missing BouncyHsm build fail loudly instead of silently skipping the
/// whole <c>[Fact(SkipUnless = nameof(BouncyHsmAvailable))]</c> suite while CI stays green. BouncyHsm
/// is built only on the legs that declare it with <c>PKCS11_TEST_EXPECT_BOUNCYHSM=1</c> (no arm64
/// client ships upstream), so the guard is keyed on that marker.
/// </summary>
[NoBackendCollection("Reads the fixture's static File.Exists probe only — it never starts the server " +
                     "or loads the module, so serializing it against the BouncyHsm collection would buy nothing.")]
public sealed class BouncyHsmAvailabilityTests
{
    [Fact]
    public void BouncyHsm_IsAvailable_WhereTheCiLegExpectsIt()
    {
        bool expected = string.Equals(
            Environment.GetEnvironmentVariable("PKCS11_TEST_EXPECT_BOUNCYHSM"), "1", StringComparison.Ordinal);

        if (!expected) return;

        Assert.True(BouncyHsmBackendFixture.BouncyHsmAvailable,
            "This CI leg declares PKCS11_TEST_EXPECT_BOUNCYHSM=1 but no BouncyHsm server and native " +
            $"client were found under {Settings.BouncyHsmDirectory}. Refusing to let the BouncyHsm " +
            "integration suite skip silently and report green.");
    }
}
