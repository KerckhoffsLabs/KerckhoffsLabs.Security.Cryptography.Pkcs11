using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// BaseKeyProtection over FreeHSM — thin wrapper over <see cref="BaseKeyProtectionTestCases"/>. A regression case
/// for GHSA-4x45-2v79-28cj, fixed in FreeHSM 2.6.0.
/// </summary>
[Collection("FreeHsm")]
public sealed class BaseKeyProtectionTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.Derivations), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void KeyMadeFromAProtectedKey_KeepsItsProtection(string derivation) => BaseKeyProtectionTestCases.Assert_KeyMadeFromAProtectedKey_KeepsItsProtection(_backend, derivation);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.SecondKeyMechanismLists), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void SecondKeysAllowedMechanisms_AreEnforced(string list)
    {
        if (list == "excludes it" && !FreeHsmBackendFixture.FreeHsmChecksTheSecondKeysAllowedMechanisms)
            Assert.Skip("FreeHSM ignores the second key's CKA_ALLOWED_MECHANISMS (FreeHsmBackendFixture.FreeHsmChecksTheSecondKeysAllowedMechanisms).");
        BaseKeyProtectionTestCases.Assert_SecondKeysAllowedMechanisms_AreEnforced(_backend, list);
    }

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.OneByteDerivations), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void OneByteKeyFromAProtectedKey_GivesNoByteAway(string derivation) => BaseKeyProtectionTestCases.Assert_OneByteKeyFromAProtectedKey_GivesNoByteAway(_backend, derivation);
}
