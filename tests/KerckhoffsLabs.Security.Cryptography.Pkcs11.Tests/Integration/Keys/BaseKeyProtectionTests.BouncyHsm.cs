using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>BaseKeyProtection over BouncyHsm — thin wrapper over <see cref="BaseKeyProtectionTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class BaseKeyProtectionTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.Derivations), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void KeyMadeFromAProtectedKey_KeepsItsProtection(string derivation)
    {
        if (derivation.StartsWith("XOR_BASE_AND_DATA", StringComparison.Ordinal) && !BouncyHsmBackendFixture.BouncyHsmRefusesAnXorKeyWithoutALength)
            Assert.Skip("BouncyHsm makes a 1-byte CKM_XOR_BASE_AND_DATA key when the template gives a key type but no length.");
        BaseKeyProtectionTestCases.Assert_KeyMadeFromAProtectedKey_KeepsItsProtection(_backend, derivation);
    }
}
