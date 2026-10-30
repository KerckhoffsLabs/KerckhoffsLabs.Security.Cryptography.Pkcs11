using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// CI-health guard: makes a missing wolfPKCS11 build fail loudly instead of silently skipping the
/// whole <c>[Fact(SkipUnless = nameof(WolfPkcs11Available))]</c> suite while CI stays green — without it, a
/// build regression would erase the wolfPKCS11 cross-check unnoticed.
/// Like Kryoptic and FreeHSM (and unlike SoftHSM, built on every leg), wolfPKCS11 is built only where
/// the CI leg declares it via <c>PKCS11_TEST_EXPECT_WOLFPKCS11=1</c> on its test step, so the guard is keyed
/// on that marker rather than on the <c>CI</c> variable.
/// </summary>
[NoBackendCollection("Reads the fixture's static File.Exists probe only — it never loads or " +
                     "initializes the module, so serializing it against the WolfPkcs11 collection would buy nothing.")]
public sealed class WolfPkcs11AvailabilityTests
{
    [Fact]
    public void WolfPkcs11_IsAvailable_WhereTheCiLegExpectsIt()
    {
        bool expected = string.Equals(
            Environment.GetEnvironmentVariable("PKCS11_TEST_EXPECT_WOLFPKCS11"), "1", StringComparison.Ordinal);

        // Local runs and legs without a wolfPKCS11 build make no promise — nothing to guard.
        if (!expected) return;

        Assert.True(WolfPkcs11BackendFixture.WolfPkcs11Available,
            "This CI leg declares PKCS11_TEST_EXPECT_WOLFPKCS11=1 but no loadable wolfPKCS11 library " +
            "was found next to the test assembly. Refusing to let the wolfPKCS11 integration suite " +
            "skip silently and report green.");
    }
}
