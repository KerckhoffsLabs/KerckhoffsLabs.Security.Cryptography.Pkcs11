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
        if (!BouncyHsmBackendFixture.BaseKeyProtectionIsKept(derivation))
            Assert.Skip("BouncyHsm gives a key derived from data and a key the template's protection, not the base key's (harrison314/BouncyHsm#141)");
        BaseKeyProtectionTestCases.Assert_KeyMadeFromAProtectedKey_KeepsItsProtection(_backend, derivation);
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.SecondKeyMechanismLists), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void SecondKeysAllowedMechanisms_AreEnforced(string list)
    {
        if (list == "excludes it" && !BouncyHsmBackendFixture.BouncyHsmChecksTheSecondKeysAllowedMechanisms)
            Assert.Skip("BouncyHsm ignores the second key's CKA_ALLOWED_MECHANISMS (BouncyHsmBackendFixture.BouncyHsmChecksTheSecondKeysAllowedMechanisms).");
        BaseKeyProtectionTestCases.Assert_SecondKeysAllowedMechanisms_AreEnforced(_backend, list);
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.OneByteDerivations), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void OneByteKeyFromAProtectedKey_GivesNoByteAway(string derivation)
    {
        if (!BouncyHsmBackendFixture.BouncyHsmKeepsAProtectedKeysBytesFromADigest)
            Assert.Skip("BouncyHsm digests a one-byte key made from a protected key (BouncyHsmBackendFixture.BouncyHsmKeepsAProtectedKeysBytesFromADigest).");
        BaseKeyProtectionTestCases.Assert_OneByteKeyFromAProtectedKey_GivesNoByteAway(_backend, derivation);
    }
}
