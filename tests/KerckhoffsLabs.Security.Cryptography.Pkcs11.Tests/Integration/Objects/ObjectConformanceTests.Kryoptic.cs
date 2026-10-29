using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>ObjectConformance over Kryoptic — thin wrapper over <see cref="ObjectConformanceTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class ObjectConformanceTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    public static TheoryData<CKA> ReadOnlyKeyAttributesHere => [CKA.CKA_LOCAL, CKA.CKA_ALWAYS_SENSITIVE, CKA.CKA_NEVER_EXTRACTABLE, CKA.CKA_KEY_GEN_MECHANISM];

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void SetAttributeValue_LabelAndId_RoundTrip() => ObjectConformanceTestCases.Assert_SetAttributeValue_LabelAndId_RoundTrip(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void UnmodifiableObject_RefusesChanges() => ObjectConformanceTestCases.Assert_UnmodifiableObject_RefusesChanges(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void UncopyableObject_RefusesCopies() => ObjectConformanceTestCases.Assert_UncopyableObject_RefusesCopies(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void UndestroyableObject_RefusesDestruction() => ObjectConformanceTestCases.Assert_UndestroyableObject_RefusesDestruction(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void CopyObject_KeepsTheProtection() => ObjectConformanceTestCases.Assert_CopyObject_KeepsTheProtection(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ProvenanceAttributes_TellGeneratedFromImported() => ObjectConformanceTestCases.Assert_ProvenanceAttributes_TellGeneratedFromImported(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void LibraryGenerators_NeverGrantDerive() => ObjectConformanceTestCases.Assert_LibraryGenerators_NeverGrantDerive(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void MixedRead_FillsTheReadableAttributes() => ObjectConformanceTestCases.Assert_MixedRead_FillsTheReadableAttributes(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Application_RoundTripsAndIsSearchable() => ObjectConformanceTestCases.Assert_Application_RoundTripsAndIsSearchable(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void KeyDates_RoundTrip() => ObjectConformanceTestCases.Assert_KeyDates_RoundTrip(_backend);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(ReadOnlyKeyAttributesHere))]
    public void SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(CKA attribute)
    {
        ObjectConformanceTestCases.Assert_SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(_backend, attribute);
    }

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.OneWayFlags), MemberType = typeof(ObjectConformanceTestCases))]
    public void OneWayFlag_CannotBeUndone(CKA flag) => ObjectConformanceTestCases.Assert_OneWayFlag_CannotBeUndone(_backend, flag);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.DataValueLengths), MemberType = typeof(ObjectConformanceTestCases))]
    public void DataValue_RoundTrips(int length) => ObjectConformanceTestCases.Assert_DataValue_RoundTrips(_backend, length);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.MalformedTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void MalformedTemplate_CreatesNothing(string malformed) => ObjectConformanceTestCases.Assert_MalformedTemplate_CreatesNothing(_backend, malformed);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.SensitivePrivateKeyTypes), MemberType = typeof(ObjectConformanceTestCases))]
    public void SensitivePrivateKey_HidesItsSecretParts(string keyType) => ObjectConformanceTestCases.Assert_SensitivePrivateKey_HidesItsSecretParts(_backend, keyType);

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.IncompleteTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void IncompleteTemplate_IsTemplateIncomplete(string incomplete) => ObjectConformanceTestCases.Assert_IncompleteTemplate_IsTemplateIncomplete(_backend, incomplete);
}
