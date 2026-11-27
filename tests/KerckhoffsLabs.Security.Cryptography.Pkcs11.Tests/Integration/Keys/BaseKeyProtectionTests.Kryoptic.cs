using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>BaseKeyProtection over Kryoptic — thin wrapper over <see cref="BaseKeyProtectionTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class BaseKeyProtectionTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.Derivations), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void KeyMadeFromAProtectedKey_KeepsItsProtection(string derivation) => BaseKeyProtectionTestCases.Assert_KeyMadeFromAProtectedKey_KeepsItsProtection(_backend, derivation);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.SecondKeyMechanismLists), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void SecondKeysAllowedMechanisms_AreEnforced(string list)
    {
        if (list == "excludes it" && !KryopticBackendFixture.KryopticChecksTheSecondKeysAllowedMechanisms)
            Assert.Skip("Kryoptic ignores the second key's CKA_ALLOWED_MECHANISMS (KryopticBackendFixture.KryopticChecksTheSecondKeysAllowedMechanisms).");
        BaseKeyProtectionTestCases.Assert_SecondKeysAllowedMechanisms_AreEnforced(_backend, list);
    }

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.OneByteDerivations), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void OneByteKeyFromAProtectedKey_GivesNoByteAway(string derivation)
    {
        if (!KryopticBackendFixture.KryopticKeepsAProtectedKeysBytesFromADigest)
            Assert.Skip("Kryoptic digests a one-byte key made from a protected key (KryopticBackendFixture.KryopticKeepsAProtectedKeysBytesFromADigest).");
        BaseKeyProtectionTestCases.Assert_OneByteKeyFromAProtectedKey_GivesNoByteAway(_backend, derivation);
    }
}
