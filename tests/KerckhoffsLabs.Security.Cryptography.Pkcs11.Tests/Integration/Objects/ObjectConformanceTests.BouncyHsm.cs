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
    public void CopyObject_KeepsTheProtection()
    {
        Assert.Skip("BouncyHsm lets C_CopyObject make an unextractable key extractable (https://github.com/harrison314/BouncyHsm/issues/132).");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ProvenanceAttributes_TellGeneratedFromImported()
    {
        // BouncyHsm reports an imported key as CKA_NEVER_EXTRACTABLE, with CKM_AES_KEY_GEN as its CKA_KEY_GEN_MECHANISM.
        ObjectConformanceTestCases.Assert_ProvenanceAttributes_TellGeneratedFromImported(_backend, importedNeverExtractable: true, importedKeyGenMechanism: (ulong)CKM.CKM_AES_KEY_GEN);
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
        if (attribute == CKA.CKA_KEY_GEN_MECHANISM)
            Assert.Skip("BouncyHsm lets C_SetAttributeValue change CKA_KEY_GEN_MECHANISM.");
        if (attribute is CKA.CKA_PRIVATE or CKA.CKA_MODIFIABLE && !BouncyHsmBackendFixture.BouncyHsmFixesThePrivateAndModifiableFlags)
            Assert.Skip("BouncyHsm lets C_SetAttributeValue change CKA_PRIVATE and CKA_MODIFIABLE.");
        // BouncyHsm answers a change to CKA_CLASS with CKR_OK and leaves it as it was.
        ObjectConformanceTestCases.Assert_SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(_backend, attribute, ignored: attribute == CKA.CKA_CLASS);
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.OneWayFlags), MemberType = typeof(ObjectConformanceTestCases))]
    public void OneWayFlag_CannotBeUndone(CKA flag)
    {
        _ = flag;
        Assert.Skip("BouncyHsm lets C_SetAttributeValue undo CKA_SENSITIVE and CKA_EXTRACTABLE (https://github.com/harrison314/BouncyHsm/issues/132).");
    }

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
        if (keyType is "ML-DSA" or "ML-KEM" && !BouncyHsmBackendFixture.BouncyHsmHidesSensitivePqcPrivateKeys)
            Assert.Skip("BouncyHsm reveals the CKA_VALUE of a sensitive ML-DSA or ML-KEM private key");
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

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.UniqueIdAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm gives a copy the original's CKA_UNIQUE_ID")]
    public void UniqueId_IsTheTokensAndReadOnly() => ObjectConformanceTestCases.Assert_UniqueId_IsTheTokensAndReadOnly(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.KeyMaterialFixedAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm lets C_SetAttributeValue and C_CopyObject change a key's material")]
    [MemberData(nameof(ObjectConformanceTestCases.KeyComponents), MemberType = typeof(ObjectConformanceTestCases))]
    public void KeyComponent_IsReadOnly(string component) => ObjectConformanceTestCases.Assert_KeyComponent_IsReadOnly(_backend, component);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.ProvenanceInATemplate), MemberType = typeof(ObjectConformanceTestCases))]
    public void ProvenanceAttributeInATemplate_IsReadOnly(string row) => ObjectConformanceTestCases.Assert_ProvenanceAttributeInATemplate_IsReadOnly(_backend, row);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.MalformedAttributeRefusalAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm refuses malformed attribute values with CKR_GENERAL_ERROR or CKR_DEVICE_ERROR")]
    [MemberData(nameof(ObjectConformanceTestCases.MalformedAttributes), MemberType = typeof(ObjectConformanceTestCases))]
    public void MalformedAttribute_IsRefusedHarmlessly(string malformed)
    {
        if (malformed == "C_CreateObject with CKA_TOKEN NULL and ulValueLen 1" && !BouncyHsmBackendFixture.BouncyHsmSurvivesANullAttributeValue)
            Assert.Skip("BouncyHsm's native client crashes on a NULL CKA_TOKEN with a length");
        ObjectConformanceTestCases.Assert_MalformedAttribute_IsRefusedHarmlessly(_backend, malformed);
    }
}
