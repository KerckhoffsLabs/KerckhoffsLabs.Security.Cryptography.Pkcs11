using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Smoke;

/// <summary>
/// CI-health guard: makes a missing tpm2-pkcs11 image fail loudly instead of silently skipping the
/// whole <c>[Fact(SkipUnless = nameof(Tpm2Pkcs11Available))]</c> suite while CI stays green — without it, a
/// build regression would erase the tpm2-pkcs11 cross-check unnoticed.
/// tpm2-pkcs11 and the programs its fixture runs exist only inside the tpm2-pkcs11 image, so the guard is keyed on the
/// <c>PKCS11_TEST_EXPECT_TPM2_PKCS11=1</c> marker the CI leg that runs the tests there declares, rather
/// than on the <c>CI</c> variable.
/// </summary>
[NoBackendCollection("Reads the fixture's static File.Exists probe only — it never loads the " +
                     "module or starts the software TPM, so serializing it against the Tpm2Pkcs11 collection would buy nothing.")]
public sealed class Tpm2Pkcs11AvailabilityTests
{
    [Fact]
    public void Tpm2Pkcs11_IsAvailable_WhereTheCiLegExpectsIt()
    {
        bool expected = string.Equals(
            Environment.GetEnvironmentVariable("PKCS11_TEST_EXPECT_TPM2_PKCS11"), "1", StringComparison.Ordinal);

        // Local runs and legs outside the image make no promise — nothing to guard.
        if (!expected) return;

        Assert.True(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available,
            "This CI leg declares PKCS11_TEST_EXPECT_TPM2_PKCS11=1 but the tpm2-pkcs11 library, swtpm, tpm2-abrmd " +
            "or dbus-daemon was not found (PKCS11_TEST_TPM2_PKCS11_LIBRARY, PKCS11_TEST_SWTPM, PKCS11_TEST_TPM2_ABRMD, " +
            "PKCS11_TEST_DBUS_DAEMON). Refusing to let the tpm2-pkcs11 suite " +
            "skip silently and report green.");
    }
}
