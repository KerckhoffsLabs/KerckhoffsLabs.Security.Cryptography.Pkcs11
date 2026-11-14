using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>ObjectConformance over BouncyHsm — thin wrapper over <see cref="ObjectConformanceTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class ObjectConformanceTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SetAttributeValue_LabelAndId_RoundTrip() => ObjectConformanceTestCases.Assert_SetAttributeValue_LabelAndId_RoundTrip(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void UnmodifiableObject_RefusesChanges() => ObjectConformanceTestCases.Assert_UnmodifiableObject_RefusesChanges(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void UncopyableObject_RefusesCopies() => ObjectConformanceTestCases.Assert_UncopyableObject_RefusesCopies(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void UndestroyableObject_RefusesDestruction() => ObjectConformanceTestCases.Assert_UndestroyableObject_RefusesDestruction(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void CopyObject_KeepsTheProtection() => ObjectConformanceTestCases.Assert_CopyObject_KeepsTheProtection(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.CopyChangesNotAllowed), MemberType = typeof(ObjectConformanceTestCases))]
    public void CopyObject_CannotMakeThatChange(string change)
    {
        if (change.StartsWith("CKA_ALLOWED_MECHANISMS", StringComparison.Ordinal) && !BouncyHsmBackendFixture.AllowedMechanismsCopyAvailable)
            Assert.Skip("BouncyHsm lets a copy change CKA_ALLOWED_MECHANISMS.");
        ObjectConformanceTestCases.Assert_CopyObject_CannotMakeThatChange(_backend, change);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ProvenanceAttributes_TellGeneratedFromImported()
    {
        // BouncyHsm reports CKM_AES_KEY_GEN as the CKA_KEY_GEN_MECHANISM of an imported key.
        ObjectConformanceTestCases.Assert_ProvenanceAttributes_TellGeneratedFromImported(_backend, importedKeyGenMechanism: (ulong)CKM.CKM_AES_KEY_GEN);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void LibraryGenerators_NeverGrantDerive() => ObjectConformanceTestCases.Assert_LibraryGenerators_NeverGrantDerive(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void MixedRead_FillsTheReadableAttributes() => ObjectConformanceTestCases.Assert_MixedRead_FillsTheReadableAttributes(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Application_RoundTripsAndIsSearchable() => ObjectConformanceTestCases.Assert_Application_RoundTripsAndIsSearchable(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void KeyDates_RoundTrip() => ObjectConformanceTestCases.Assert_KeyDates_RoundTrip(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.ReadOnlyKeyAttributes), MemberType = typeof(ObjectConformanceTestCases))]
    public void SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(CKA attribute)
    {
        if (attribute is CKA.CKA_MODIFIABLE && !BouncyHsmBackendFixture.BouncyHsmFixesTheModifiableFlag)
            Assert.Skip("BouncyHsm lets C_SetAttributeValue change CKA_MODIFIABLE.");
        ObjectConformanceTestCases.Assert_SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(_backend, attribute);
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.OneWayFlags), MemberType = typeof(ObjectConformanceTestCases))]
    public void OneWayFlag_CannotBeUndone(CKA flag) => ObjectConformanceTestCases.Assert_OneWayFlag_CannotBeUndone(_backend, flag);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.DataValueLengths), MemberType = typeof(ObjectConformanceTestCases))]
    public void DataValue_RoundTrips(int length) => ObjectConformanceTestCases.Assert_DataValue_RoundTrips(_backend, length);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.MalformedTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void MalformedTemplate_CreatesNothing(string malformed)
    {
        // BouncyHsm refuses an AES key with no value, or of 13 bytes, with CKR_GENERAL_ERROR.
        ObjectConformanceTestCases.Assert_MalformedTemplate_CreatesNothing(_backend, malformed, [CKR.CKR_GENERAL_ERROR]);
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.SensitivePrivateKeyTypes), MemberType = typeof(ObjectConformanceTestCases))]
    public void SensitivePrivateKey_HidesItsSecretParts(string keyType)
    {
        ObjectConformanceTestCases.Assert_SensitivePrivateKey_HidesItsSecretParts(_backend, keyType);
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.IncompleteTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void IncompleteTemplate_IsTemplateIncomplete(string incomplete)
    {
        if (incomplete is "RSA public key without CKA_MODULUS" or "RSA private key without CKA_MODULUS"
            or "EC public key without CKA_EC_PARAMS" or "EC private key without CKA_EC_PARAMS"
            && !BouncyHsmBackendFixture.BouncyHsmReportsAMissingKeyAttributeAsIncomplete)
            Assert.Skip("BouncyHsm answers a key without CKA_MODULUS or CKA_EC_PARAMS with CKR_ATTRIBUTE_VALUE_INVALID");
        if (incomplete == "secret key without CKA_KEY_TYPE" && !BouncyHsmBackendFixture.BouncyHsmRefusesASecretKeyWithoutAKeyType)
            Assert.Skip("BouncyHsm makes a secret key without CKA_KEY_TYPE");
        ObjectConformanceTestCases.Assert_IncompleteTemplate_IsTemplateIncomplete(_backend, incomplete);
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.InconsistentTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void InconsistentTemplate_IsTemplateInconsistent(string inconsistent)
    {
        if (inconsistent.StartsWith("EC key pair", StringComparison.Ordinal) && !BouncyHsmBackendFixture.BouncyHsmChecksTheKeyPairTemplatesClassAndKeyType)
            Assert.Skip("BouncyHsm generates an EC key pair whose templates give another class or key type");
        ObjectConformanceTestCases.Assert_InconsistentTemplate_IsTemplateInconsistent(_backend, inconsistent);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.UniqueIdReadOnlyAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm lets C_SetAttributeValue change CKA_UNIQUE_ID")]
    public void UniqueId_IsTheTokensAndReadOnly() => ObjectConformanceTestCases.Assert_UniqueId_IsTheTokensAndReadOnly(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.KeyComponents), MemberType = typeof(ObjectConformanceTestCases))]
    public void KeyComponent_IsReadOnly(string component)
    {
        if (component is "RSA CKA_PUBLIC_EXPONENT" or "EC CKA_EC_POINT" && !BouncyHsmBackendFixture.BouncyHsmFixesPublicKeyComponents)
            Assert.Skip("BouncyHsm lets C_SetAttributeValue change an RSA public exponent or an EC point.");
        ObjectConformanceTestCases.Assert_KeyComponent_IsReadOnly(_backend, component);
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.ProvenanceInATemplate), MemberType = typeof(ObjectConformanceTestCases))]
    public void ProvenanceAttributeInATemplate_IsReadOnly(string row) => ObjectConformanceTestCases.Assert_ProvenanceAttributeInATemplate_IsReadOnly(_backend, row);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.MalformedAttributes), MemberType = typeof(ObjectConformanceTestCases))]
    public void MalformedAttribute_IsRefusedHarmlessly(string malformed) => ObjectConformanceTestCases.Assert_MalformedAttribute_IsRefusedHarmlessly(_backend, malformed);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void CopyObject_KeepsCkaToken() => ObjectConformanceTestCases.Assert_CopyObject_KeepsCkaToken(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void CopyObject_KeepsADataObjectsFields() => ObjectConformanceTestCases.Assert_CopyObject_KeepsADataObjectsFields(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void UncopyableObject_StaysUncopyable() => ObjectConformanceTestCases.Assert_UncopyableObject_StaysUncopyable(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void StorageControls_DefaultToTrue() => ObjectConformanceTestCases.Assert_StorageControls_DefaultToTrue(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.RefusedKeyPairs), MemberType = typeof(ObjectConformanceTestCases))]
    public void RefusedKeyPairGeneration_LeavesNothing(string refused) => ObjectConformanceTestCases.Assert_RefusedKeyPairGeneration_LeavesNothing(_backend, refused);
}
