using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>KeyProvenance over NSS — thin wrapper over <see cref="KeyProvenanceTestCases"/>.</summary>
[Collection("Nss")]
public sealed class KeyProvenanceTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    // NSS reports CKA_LOCAL false on the keys it generates; see NssBackendFixture.SupportsLocalOnGeneratedKeys.
    [Fact(SkipUnless = nameof(NssBackendFixture.LocalOnGeneratedKeysAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.LocalOnGeneratedKeysAvailable))]
    public void GeneratedSecretKey_IsLocal() => KeyProvenanceTestCases.Assert_GeneratedSecretKey_IsLocal(_backend);

    // NSS reports CKA_LOCAL false on the keys it generates; see NssBackendFixture.SupportsLocalOnGeneratedKeys.
    [Fact(SkipUnless = nameof(NssBackendFixture.LocalOnGeneratedKeysAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.LocalOnGeneratedKeysAvailable))]
    public void GeneratedKeyPair_IsLocal() => KeyProvenanceTestCases.Assert_GeneratedKeyPair_IsLocal(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ImportedSecretKey_IsNotLocal() => KeyProvenanceTestCases.Assert_ImportedSecretKey_IsNotLocal(_backend);
}
