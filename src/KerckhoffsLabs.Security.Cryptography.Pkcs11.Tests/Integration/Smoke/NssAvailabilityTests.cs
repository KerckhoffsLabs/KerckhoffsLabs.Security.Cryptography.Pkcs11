using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// CI-health guard: makes a missing NSS softoken fail loudly instead of silently skipping the whole
/// <c>[ConditionalFact(NssAvailable)]</c> suite while CI stays green — without it, a build or staging
/// regression would erase the third-real-backend cross-check unnoticed. NSS is built from source only
/// on its dedicated leg, which declares the promise with <c>PKCS11_TEST_EXPECT_NSS=1</c> on its test
/// step, so the guard is keyed on that marker rather than on the generic <c>CI</c> variable.
/// </summary>
public sealed class NssAvailabilityTests
{
    [Fact]
    public void Nss_IsAvailable_WhereTheCiLegExpectsIt()
    {
        bool expected = string.Equals(
            Environment.GetEnvironmentVariable("PKCS11_TEST_EXPECT_NSS"), "1", StringComparison.Ordinal);

        // Local runs and legs without NSS make no promise — nothing to guard.
        if (!expected) return;

        Assert.True(NssBackendFixture.NssAvailable,
            "This CI leg declares PKCS11_TEST_EXPECT_NSS=1 but no loadable NSS softoken is configured " +
            "(PKCS11_TEST_NSS_LIBRARY unset or pointing at a missing libsoftokn3.so, and none staged by " +
            "build-nss.sh). Refusing to let the NSS integration suite skip silently and report green.");
    }
}
