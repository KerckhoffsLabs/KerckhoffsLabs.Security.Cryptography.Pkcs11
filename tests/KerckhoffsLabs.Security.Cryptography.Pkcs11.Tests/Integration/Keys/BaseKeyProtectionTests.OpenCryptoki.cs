using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>BaseKeyProtection over opencryptoki — thin wrapper over <see cref="BaseKeyProtectionTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class BaseKeyProtectionTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.Derivations), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void KeyMadeFromAProtectedKey_KeepsItsProtection(string derivation) => BaseKeyProtectionTestCases.Assert_KeyMadeFromAProtectedKey_KeepsItsProtection(_backend, derivation);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.SecondKeyMechanismLists), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void SecondKeysAllowedMechanisms_AreEnforced(string list) => BaseKeyProtectionTestCases.Assert_SecondKeysAllowedMechanisms_AreEnforced(_backend, list);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(BaseKeyProtectionTestCases.OneByteDerivations), MemberType = typeof(BaseKeyProtectionTestCases))]
    public void OneByteKeyFromAProtectedKey_GivesNoByteAway(string derivation) => BaseKeyProtectionTestCases.Assert_OneByteKeyFromAProtectedKey_GivesNoByteAway(_backend, derivation);
}
