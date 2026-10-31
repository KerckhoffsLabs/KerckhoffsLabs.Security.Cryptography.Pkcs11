using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>KeyProvenance over SoftHsm2 — thin wrapper over <see cref="KeyProvenanceTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class KeyProvenanceTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void GeneratedSecretKey_IsLocal() => KeyProvenanceTestCases.Assert_GeneratedSecretKey_IsLocal(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void GeneratedKeyPair_IsLocal() => KeyProvenanceTestCases.Assert_GeneratedKeyPair_IsLocal(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ImportedSecretKey_IsNotLocal() => KeyProvenanceTestCases.Assert_ImportedSecretKey_IsNotLocal(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void CopyOfAKey_KeepsCkaLocal() => KeyProvenanceTestCases.Assert_CopyOfAKey_KeepsCkaLocal(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Pbkdf2Key_RecordsItsGeneration() => KeyProvenanceTestCases.Assert_Pbkdf2Key_RecordsItsGeneration(_backend);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(KeyProvenanceTestCases.DerivationMechanisms), MemberType = typeof(KeyProvenanceTestCases))]
    public void DerivedKey_TakesItsHistoryFromTheBase(string derivation) => KeyProvenanceTestCases.Assert_DerivedKey_TakesItsHistoryFromTheBase(_backend, derivation);
}
