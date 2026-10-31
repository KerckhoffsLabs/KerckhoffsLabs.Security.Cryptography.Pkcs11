using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>KeyProvenance over Kryoptic — thin wrapper over <see cref="KeyProvenanceTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class KeyProvenanceTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GeneratedSecretKey_IsLocal() => KeyProvenanceTestCases.Assert_GeneratedSecretKey_IsLocal(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GeneratedKeyPair_IsLocal() => KeyProvenanceTestCases.Assert_GeneratedKeyPair_IsLocal(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ImportedSecretKey_IsNotLocal() => KeyProvenanceTestCases.Assert_ImportedSecretKey_IsNotLocal(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void CopyOfAKey_KeepsCkaLocal() => KeyProvenanceTestCases.Assert_CopyOfAKey_KeepsCkaLocal(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Pbkdf2Key_RecordsItsGeneration() => KeyProvenanceTestCases.Assert_Pbkdf2Key_RecordsItsGeneration(_backend);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(KeyProvenanceTestCases.DerivationMechanisms), MemberType = typeof(KeyProvenanceTestCases))]
    public void DerivedKey_TakesItsHistoryFromTheBase(string derivation)
    {
        if (derivation == "ECDH" && !KryopticBackendFixture.KryopticDerivesAnEcdhKeysHistoryFromTheBase)
            Assert.Skip("Kryoptic makes a key derived with ECDH from an imported base CKA_ALWAYS_SENSITIVE");
        KeyProvenanceTestCases.Assert_DerivedKey_TakesItsHistoryFromTheBase(_backend, derivation);
    }
}
