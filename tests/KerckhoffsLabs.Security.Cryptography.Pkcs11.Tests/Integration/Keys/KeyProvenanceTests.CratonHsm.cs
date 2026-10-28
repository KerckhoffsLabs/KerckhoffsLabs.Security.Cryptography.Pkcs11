using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>KeyProvenance over Craton HSM — thin wrapper over <see cref="KeyProvenanceTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class KeyProvenanceTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    // Craton HSM keeps no CKA_LOCAL; see CratonHsmBackendFixture.SupportsLocalAttribute.
    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.LocalAttributeAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.LocalAttributeAvailable))]
    public void GeneratedSecretKey_IsLocal() => KeyProvenanceTestCases.Assert_GeneratedSecretKey_IsLocal(_backend);

    // Craton HSM keeps no CKA_LOCAL; see CratonHsmBackendFixture.SupportsLocalAttribute.
    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.LocalAttributeAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.LocalAttributeAvailable))]
    public void GeneratedKeyPair_IsLocal() => KeyProvenanceTestCases.Assert_GeneratedKeyPair_IsLocal(_backend);

    // Craton HSM keeps no CKA_LOCAL; see CratonHsmBackendFixture.SupportsLocalAttribute.
    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.LocalAttributeAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.LocalAttributeAvailable))]
    public void ImportedSecretKey_IsNotLocal() => KeyProvenanceTestCases.Assert_ImportedSecretKey_IsNotLocal(_backend);
}
