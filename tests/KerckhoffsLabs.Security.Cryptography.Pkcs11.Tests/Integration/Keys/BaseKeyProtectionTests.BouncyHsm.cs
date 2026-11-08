using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>BaseKeyProtection over BouncyHsm — thin wrapper over <see cref="BaseKeyProtectionTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class BaseKeyProtectionTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BaseKeyProtectionAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm gives the derived key the template's protection, not the base key's (harrison314/BouncyHsm#141)")]
    [MemberData(nameof(BaseKeyProtectionTestCases.Derivations), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void KeyMadeFromAProtectedKey_KeepsItsProtection(string derivation) => BaseKeyProtectionTestCases.Assert_KeyMadeFromAProtectedKey_KeepsItsProtection(_backend, derivation);
}
