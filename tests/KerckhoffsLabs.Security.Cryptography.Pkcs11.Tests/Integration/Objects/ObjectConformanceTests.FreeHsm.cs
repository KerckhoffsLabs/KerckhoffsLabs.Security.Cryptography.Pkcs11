using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>ObjectConformance over FreeHSM — thin wrapper over <see cref="ObjectConformanceTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class ObjectConformanceTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void SetAttributeValue_LabelAndId_RoundTrip() => ObjectConformanceTestCases.Assert_SetAttributeValue_LabelAndId_RoundTrip(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void UnmodifiableObject_RefusesChanges() => ObjectConformanceTestCases.Assert_UnmodifiableObject_RefusesChanges(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void UncopyableObject_RefusesCopies() => ObjectConformanceTestCases.Assert_UncopyableObject_RefusesCopies(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void UndestroyableObject_RefusesDestruction() => ObjectConformanceTestCases.Assert_UndestroyableObject_RefusesDestruction(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void CopyObject_KeepsTheProtection() => ObjectConformanceTestCases.Assert_CopyObject_KeepsTheProtection(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void ProvenanceAttributes_TellGeneratedFromImported()
    {
        // FreeHSM does not report CKA_KEY_GEN_MECHANISM, and reports an imported key as CKA_NEVER_EXTRACTABLE.
        ObjectConformanceTestCases.Assert_ProvenanceAttributes_TellGeneratedFromImported(_backend, [CKA.CKA_ALWAYS_SENSITIVE, CKA.CKA_NEVER_EXTRACTABLE], importedNeverExtractable: true);
    }

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void LibraryGenerators_NeverGrantDerive() => ObjectConformanceTestCases.Assert_LibraryGenerators_NeverGrantDerive(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void MixedRead_FillsTheReadableAttributes() => ObjectConformanceTestCases.Assert_MixedRead_FillsTheReadableAttributes(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Application_RoundTripsAndIsSearchable() => ObjectConformanceTestCases.Assert_Application_RoundTripsAndIsSearchable(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void KeyDates_RoundTrip() => ObjectConformanceTestCases.Assert_KeyDates_RoundTrip(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.ReadOnlyKeyAttributes), MemberType = typeof(ObjectConformanceTestCases))]
    public void SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(CKA attribute) => ObjectConformanceTestCases.Assert_SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(_backend, attribute);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.OneWayFlags), MemberType = typeof(ObjectConformanceTestCases))]
    public void OneWayFlag_CannotBeUndone(CKA flag) => ObjectConformanceTestCases.Assert_OneWayFlag_CannotBeUndone(_backend, flag);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.DataValueLengths), MemberType = typeof(ObjectConformanceTestCases))]
    public void DataValue_RoundTrips(int length) => ObjectConformanceTestCases.Assert_DataValue_RoundTrips(_backend, length);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.MalformedTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void MalformedTemplate_CreatesNothing(string malformed)
    {
        // FreeHSM creates an AES key of 13 bytes.
        ObjectConformanceTestCases.Assert_MalformedTemplate_CreatesNothing(_backend, malformed, acceptedByTheBackend: malformed == "an AES key of 13 bytes");
    }

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.SensitivePrivateKeyTypes), MemberType = typeof(ObjectConformanceTestCases))]
    public void SensitivePrivateKey_HidesItsSecretParts(string keyType)
    {
        if (keyType == "RSA" && !FreeHsmBackendFixture.FreeHsmReportsRsaPrivatePartsAsSensitive)
            Assert.Skip("FreeHSM answers a sensitive RSA key's private exponent with CKR_ATTRIBUTE_TYPE_INVALID");
        ObjectConformanceTestCases.Assert_SensitivePrivateKey_HidesItsSecretParts(_backend, keyType);
    }

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.IncompleteTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void IncompleteTemplate_IsTemplateIncomplete(string incomplete)
    {
        if (incomplete is "RSA key pair without CKA_MODULUS_BITS" or "EC key pair without CKA_EC_PARAMS" or "EC private key without CKA_EC_PARAMS"
            && !FreeHsmBackendFixture.FreeHsmRequiresTheKeyAttributes)
            Assert.Skip("FreeHSM generates a key pair without CKA_MODULUS_BITS or CKA_EC_PARAMS");
        ObjectConformanceTestCases.Assert_IncompleteTemplate_IsTemplateIncomplete(_backend, incomplete);
    }

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.InconsistentTemplateRefusalAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "FreeHSM makes objects whose class or key type contradicts the mechanism")]
    [MemberData(nameof(ObjectConformanceTestCases.InconsistentTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void InconsistentTemplate_IsTemplateInconsistent(string inconsistent) => ObjectConformanceTestCases.Assert_InconsistentTemplate_IsTemplateInconsistent(_backend, inconsistent);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void UniqueId_IsTheTokensAndReadOnly() => ObjectConformanceTestCases.Assert_UniqueId_IsTheTokensAndReadOnly(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.KeyComponents), MemberType = typeof(ObjectConformanceTestCases))]
    public void KeyComponent_IsReadOnly(string component)
    {
        if (component != "AES CKA_VALUE" && !FreeHsmBackendFixture.FreeHsmReportsKeyMaterialAsReadOnly)
            Assert.Skip("FreeHSM refuses a change to public key material with CKR_ATTRIBUTE_TYPE_INVALID, a new CKA_VALUE in a copy with CKR_TEMPLATE_INCONSISTENT");
        ObjectConformanceTestCases.Assert_KeyComponent_IsReadOnly(_backend, component);
    }

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.ProvenanceTemplateRefusalAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "FreeHSM takes CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE in a template")]
    [MemberData(nameof(ObjectConformanceTestCases.ProvenanceInATemplate), MemberType = typeof(ObjectConformanceTestCases))]
    public void ProvenanceAttributeInATemplate_IsReadOnly(string row) => ObjectConformanceTestCases.Assert_ProvenanceAttributeInATemplate_IsReadOnly(_backend, row);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.MalformedAttributes), MemberType = typeof(ObjectConformanceTestCases))]
    public void MalformedAttribute_IsRefusedHarmlessly(string malformed)
    {
        if (malformed == "C_FindObjectsInit with a 4-byte CKA_TOKEN" && !FreeHsmBackendFixture.FreeHsmMatchesAWrongLengthBoolean)
            Assert.Skip("FreeHSM's search with a 4-byte CKA_TOKEN finds a session object");
        ObjectConformanceTestCases.Assert_MalformedAttribute_IsRefusedHarmlessly(_backend, malformed);
    }

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void CopyObject_KeepsCkaToken() => ObjectConformanceTestCases.Assert_CopyObject_KeepsCkaToken(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.DataObjectIdAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "FreeHSM does not report a data object's CKA_OBJECT_ID")]
    public void CopyObject_KeepsADataObjectsFields() => ObjectConformanceTestCases.Assert_CopyObject_KeepsADataObjectsFields(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void UncopyableObject_StaysUncopyable() => ObjectConformanceTestCases.Assert_UncopyableObject_StaysUncopyable(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void StorageControls_DefaultToTrue() => ObjectConformanceTestCases.Assert_StorageControls_DefaultToTrue(_backend);
}
