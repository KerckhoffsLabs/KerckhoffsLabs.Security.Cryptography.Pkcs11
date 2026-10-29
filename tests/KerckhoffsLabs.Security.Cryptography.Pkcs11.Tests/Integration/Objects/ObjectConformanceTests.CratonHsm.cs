using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>ObjectConformance over Craton HSM — thin wrapper over <see cref="ObjectConformanceTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class ObjectConformanceTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SetAttributeValue_LabelAndId_RoundTrip() => ObjectConformanceTestCases.Assert_SetAttributeValue_LabelAndId_RoundTrip(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void UnmodifiableObject_RefusesChanges() => ObjectConformanceTestCases.Assert_UnmodifiableObject_RefusesChanges(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void UncopyableObject_RefusesCopies()
    {
        Assert.Skip("Craton HSM ignores CKA_COPYABLE: C_CopyObject copies the object.");
    }

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void UndestroyableObject_RefusesDestruction()
    {
        // Craton HSM refuses to destroy an undestroyable object with CKR_ATTRIBUTE_READ_ONLY.
        ObjectConformanceTestCases.Assert_UndestroyableObject_RefusesDestruction(_backend, CKR.CKR_ATTRIBUTE_READ_ONLY);
    }

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void CopyObject_KeepsTheProtection() => ObjectConformanceTestCases.Assert_CopyObject_KeepsTheProtection(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ProvenanceAttributes_TellGeneratedFromImported()
    {
        // Craton HSM reports none of CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE and CKA_KEY_GEN_MECHANISM.
        ObjectConformanceTestCases.Assert_ProvenanceAttributes_TellGeneratedFromImported(_backend, []);
    }

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void LibraryGenerators_NeverGrantDerive() => ObjectConformanceTestCases.Assert_LibraryGenerators_NeverGrantDerive(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Application_RoundTripsAndIsSearchable() => ObjectConformanceTestCases.Assert_Application_RoundTripsAndIsSearchable(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void KeyDates_RoundTrip() => ObjectConformanceTestCases.Assert_KeyDates_RoundTrip(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.ReadOnlyKeyAttributes), MemberType = typeof(ObjectConformanceTestCases))]
    public void SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(CKA attribute) => ObjectConformanceTestCases.Assert_SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(_backend, attribute);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.OneWayFlags), MemberType = typeof(ObjectConformanceTestCases))]
    public void OneWayFlag_CannotBeUndone(CKA flag) => ObjectConformanceTestCases.Assert_OneWayFlag_CannotBeUndone(_backend, flag);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.DataValueLengths), MemberType = typeof(ObjectConformanceTestCases))]
    public void DataValue_RoundTrips(int length)
    {
        // Craton HSM refuses a CKA_VALUE longer than 4 KiB here with CKR_ATTRIBUTE_VALUE_INVALID.
        ObjectConformanceTestCases.Assert_DataValue_RoundTrips(_backend, length, maxLength: 4096);
    }

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.MalformedTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void MalformedTemplate_CreatesNothing(string malformed)
    {
        // Craton HSM creates an object of an undefined class, and an AES key with no value or of 13 bytes.
        ObjectConformanceTestCases.Assert_MalformedTemplate_CreatesNothing(_backend, malformed, acceptedByTheBackend: malformed != "no CKA_CLASS");
    }

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void MixedRead_FillsTheReadableAttributes() => ObjectConformanceTestCases.Assert_MixedRead_FillsTheReadableAttributes(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.SensitivePrivateKeyTypes), MemberType = typeof(ObjectConformanceTestCases))]
    public void SensitivePrivateKey_HidesItsSecretParts(string keyType) => ObjectConformanceTestCases.Assert_SensitivePrivateKey_HidesItsSecretParts(_backend, keyType);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.IncompleteTemplateRefusalAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Craton HSM makes keys from templates without the attributes they need")]
    [MemberData(nameof(ObjectConformanceTestCases.IncompleteTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void IncompleteTemplate_IsTemplateIncomplete(string incomplete) => ObjectConformanceTestCases.Assert_IncompleteTemplate_IsTemplateIncomplete(_backend, incomplete);
}
