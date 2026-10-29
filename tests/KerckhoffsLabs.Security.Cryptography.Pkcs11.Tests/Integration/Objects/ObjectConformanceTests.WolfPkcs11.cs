using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>ObjectConformance over wolfPKCS11 — thin wrapper over <see cref="ObjectConformanceTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class ObjectConformanceTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void SetAttributeValue_LabelAndId_RoundTrip() => ObjectConformanceTestCases.Assert_SetAttributeValue_LabelAndId_RoundTrip(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void UnmodifiableObject_RefusesChanges() => ObjectConformanceTestCases.Assert_UnmodifiableObject_RefusesChanges(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void UncopyableObject_RefusesCopies() => ObjectConformanceTestCases.Assert_UncopyableObject_RefusesCopies(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void UndestroyableObject_RefusesDestruction() => ObjectConformanceTestCases.Assert_UndestroyableObject_RefusesDestruction(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void CopyObject_KeepsTheProtection() => ObjectConformanceTestCases.Assert_CopyObject_KeepsTheProtection(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ProvenanceAttributes_TellGeneratedFromImported() => ObjectConformanceTestCases.Assert_ProvenanceAttributes_TellGeneratedFromImported(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WrapTemplateAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 refuses CKA_WRAP_TEMPLATE and CKA_UNWRAP_TEMPLATE in C_GenerateKey")]
    public void LibraryGenerators_NeverGrantDerive() => ObjectConformanceTestCases.Assert_LibraryGenerators_NeverGrantDerive(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void MixedRead_FillsTheReadableAttributes() => ObjectConformanceTestCases.Assert_MixedRead_FillsTheReadableAttributes(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Application_RoundTripsAndIsSearchable() => ObjectConformanceTestCases.Assert_Application_RoundTripsAndIsSearchable(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void KeyDates_RoundTrip() => ObjectConformanceTestCases.Assert_KeyDates_RoundTrip(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(ObjectConformanceTestCases.ReadOnlyKeyAttributes), MemberType = typeof(ObjectConformanceTestCases))]
    public void SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(CKA attribute) => ObjectConformanceTestCases.Assert_SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(_backend, attribute);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(ObjectConformanceTestCases.OneWayFlags), MemberType = typeof(ObjectConformanceTestCases))]
    public void OneWayFlag_CannotBeUndone(CKA flag) => ObjectConformanceTestCases.Assert_OneWayFlag_CannotBeUndone(_backend, flag);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(ObjectConformanceTestCases.DataValueLengths), MemberType = typeof(ObjectConformanceTestCases))]
    public void DataValue_RoundTrips(int length) => ObjectConformanceTestCases.Assert_DataValue_RoundTrips(_backend, length);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(ObjectConformanceTestCases.MalformedTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void MalformedTemplate_CreatesNothing(string malformed)
    {
        // wolfPKCS11 answers an undefined CKA_CLASS with CKR_TEMPLATE_INCOMPLETE, where PKCS#11 v3.2 has
        // CKR_ATTRIBUTE_VALUE_INVALID for a value it does not know, and creates an AES key of 13 bytes,
        // which §6.7 does not allow.
        ObjectConformanceTestCases.Assert_MalformedTemplate_CreatesNothing(
            _backend, malformed, [CKR.CKR_TEMPLATE_INCOMPLETE], acceptedByTheBackend: malformed == "an AES key of 13 bytes");
    }
}
