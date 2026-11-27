using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>BaseKeyProtection over NSS softoken — thin wrapper over <see cref="BaseKeyProtectionTestCases"/>.</summary>
[Collection("Nss")]
public sealed class BaseKeyProtectionTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.Derivations), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void KeyMadeFromAProtectedKey_KeepsItsProtection(string derivation)
    {
        // Before 3.97, CKM_CONCATENATE_BASE_AND_KEY forced CKA_SENSITIVE onto the second key instead of the
        // derived key. Fixed by Bug 1871630 (PK11_ConcatSymKeys); the second key's CKA_EXTRACTABLE is still ignored.
        if (derivation.Contains("protected second key", StringComparison.Ordinal))
        {
            _backend.RequireSoftoken(3, 97, "the derived key does not take the second key's protection (Bug 1871630)");
            if (derivation.EndsWith("unextractable only", StringComparison.Ordinal) && !NssBackendFixture.SecondKeyExtractabilityAvailable)
                Assert.Skip("NSS ignores the second key's CKA_EXTRACTABLE (NssBackendFixture.TakesTheSecondKeysExtractability).");
        }

        BaseKeyProtectionTestCases.Assert_KeyMadeFromAProtectedKey_KeepsItsProtection(_backend, derivation);
    }

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.SecondKeyMechanismLists), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void SecondKeysAllowedMechanisms_AreEnforced(string list)
    {
        if (list == "excludes it" && !NssBackendFixture.NssChecksTheSecondKeysAllowedMechanisms)
            Assert.Skip("NSS ignores the second key's CKA_ALLOWED_MECHANISMS (NssBackendFixture.NssChecksTheSecondKeysAllowedMechanisms).");
        BaseKeyProtectionTestCases.Assert_SecondKeysAllowedMechanisms_AreEnforced(_backend, list);
    }

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.OneByteDerivations), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void OneByteKeyFromAProtectedKey_GivesNoByteAway(string derivation)
    {
        if (!NssBackendFixture.NssKeepsAProtectedKeysBytesFromADigest)
            Assert.Skip("NSS digests a one-byte key made from a protected key (NssBackendFixture.NssKeepsAProtectedKeysBytesFromADigest).");
        BaseKeyProtectionTestCases.Assert_OneByteKeyFromAProtectedKey_GivesNoByteAway(_backend, derivation);
    }
}
