using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>BaseKeyProtection over Kryoptic — thin wrapper over <see cref="BaseKeyProtectionTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class BaseKeyProtectionTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.Derivations), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void KeyMadeFromAProtectedKey_KeepsItsProtection(string derivation)
    {
        if (!derivation.StartsWith("CONCATENATE_BASE_AND_KEY", StringComparison.Ordinal) && !KryopticBackendFixture.BaseKeyProtectionAvailable)
            Assert.Skip("Kryoptic gives the derived key the template's protection, not the base key's (latchset/kryoptic#577).");
        BaseKeyProtectionTestCases.Assert_KeyMadeFromAProtectedKey_KeepsItsProtection(_backend, derivation);
    }
}
