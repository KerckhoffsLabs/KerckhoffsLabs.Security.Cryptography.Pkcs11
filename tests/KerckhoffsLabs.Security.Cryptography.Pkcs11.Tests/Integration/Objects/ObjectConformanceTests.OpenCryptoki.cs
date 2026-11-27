using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>ObjectConformance over opencryptoki — thin wrapper over <see cref="ObjectConformanceTestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class ObjectConformanceTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void SetAttributeValue_LabelAndId_RoundTrip() => ObjectConformanceTestCases.Assert_SetAttributeValue_LabelAndId_RoundTrip(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void UnmodifiableObject_RefusesChanges() => ObjectConformanceTestCases.Assert_UnmodifiableObject_RefusesChanges(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void UncopyableObject_RefusesCopies() => ObjectConformanceTestCases.Assert_UncopyableObject_RefusesCopies(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void UndestroyableObject_RefusesDestruction() => ObjectConformanceTestCases.Assert_UndestroyableObject_RefusesDestruction(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void CopyObject_KeepsTheProtection() => ObjectConformanceTestCases.Assert_CopyObject_KeepsTheProtection(_backend);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.CopyChangesNotAllowed), MemberType = typeof(ObjectConformanceTestCases))]
    public void CopyObject_CannotMakeThatChange(string change) => ObjectConformanceTestCases.Assert_CopyObject_CannotMakeThatChange(_backend, change);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ProvenanceAttributes_TellGeneratedFromImported() => ObjectConformanceTestCases.Assert_ProvenanceAttributes_TellGeneratedFromImported(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void LibraryGenerators_NeverGrantDerive() => ObjectConformanceTestCases.Assert_LibraryGenerators_NeverGrantDerive(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void MixedRead_FillsTheReadableAttributes() => ObjectConformanceTestCases.Assert_MixedRead_FillsTheReadableAttributes(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Application_RoundTripsAndIsSearchable() => ObjectConformanceTestCases.Assert_Application_RoundTripsAndIsSearchable(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void KeyDates_RoundTrip() => ObjectConformanceTestCases.Assert_KeyDates_RoundTrip(_backend);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.ReadOnlyKeyAttributes), MemberType = typeof(ObjectConformanceTestCases))]
    public void SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(CKA attribute) => ObjectConformanceTestCases.Assert_SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(_backend, attribute);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.OneWayFlags), MemberType = typeof(ObjectConformanceTestCases))]
    public void OneWayFlag_CannotBeUndone(CKA flag) => ObjectConformanceTestCases.Assert_OneWayFlag_CannotBeUndone(_backend, flag);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.DataValueLengths), MemberType = typeof(ObjectConformanceTestCases))]
    public void DataValue_RoundTrips(int length) => ObjectConformanceTestCases.Assert_DataValue_RoundTrips(_backend, length);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.MalformedTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void MalformedTemplate_CreatesNothing(string malformed) => ObjectConformanceTestCases.Assert_MalformedTemplate_CreatesNothing(_backend, malformed);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.SensitivePrivateKeyTypes), MemberType = typeof(ObjectConformanceTestCases))]
    public void SensitivePrivateKey_HidesItsSecretParts(string keyType) => ObjectConformanceTestCases.Assert_SensitivePrivateKey_HidesItsSecretParts(_backend, keyType);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.IncompleteTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void IncompleteTemplate_IsTemplateIncomplete(string incomplete)
    {
        if (incomplete == "secret key without CKA_KEY_TYPE" && !OpenCryptokiBackendFixture.OpenCryptokiReportsAMissingKeyTypeAsIncomplete)
            Assert.Skip("opencryptoki refuses a secret key without CKA_KEY_TYPE with CKR_TEMPLATE_INCONSISTENT");
        ObjectConformanceTestCases.Assert_IncompleteTemplate_IsTemplateIncomplete(_backend, incomplete);
    }

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.InconsistentTemplates), MemberType = typeof(ObjectConformanceTestCases))]
    public void InconsistentTemplate_IsTemplateInconsistent(string inconsistent)
    {
        if (inconsistent == "EC key pair with an RSA private key" && !OpenCryptokiBackendFixture.OpenCryptokiChecksAPrivateKeyTypeOfZero)
            Assert.Skip("opencryptoki does not see CKK_RSA (0) in an EC key pair's private template, and fails later with CKR_TEMPLATE_INCOMPLETE");
        if (inconsistent == "AES key generated as CKK_RSA" && !OpenCryptokiBackendFixture.OpenCryptokiRefusesAnAesKeyGeneratedAsRsa)
            Assert.Skip("opencryptoki generates an AES key whose template asks for CKK_RSA (0)");
        ObjectConformanceTestCases.Assert_InconsistentTemplate_IsTemplateInconsistent(_backend, inconsistent);
    }

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void UniqueId_IsTheTokensAndReadOnly() => ObjectConformanceTestCases.Assert_UniqueId_IsTheTokensAndReadOnly(_backend);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.KeyComponents), MemberType = typeof(ObjectConformanceTestCases))]
    public void KeyComponent_IsReadOnly(string component) => ObjectConformanceTestCases.Assert_KeyComponent_IsReadOnly(_backend, component);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.ProvenanceInATemplate), MemberType = typeof(ObjectConformanceTestCases))]
    public void ProvenanceAttributeInATemplate_IsReadOnly(string row) => ObjectConformanceTestCases.Assert_ProvenanceAttributeInATemplate_IsReadOnly(_backend, row);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.MalformedAttributes), MemberType = typeof(ObjectConformanceTestCases))]
    public void MalformedAttribute_IsRefusedHarmlessly(string malformed) => ObjectConformanceTestCases.Assert_MalformedAttribute_IsRefusedHarmlessly(_backend, malformed);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void CopyObject_KeepsCkaToken() => ObjectConformanceTestCases.Assert_CopyObject_KeepsCkaToken(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void CopyObject_KeepsADataObjectsFields() => ObjectConformanceTestCases.Assert_CopyObject_KeepsADataObjectsFields(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void UncopyableObject_StaysUncopyable() => ObjectConformanceTestCases.Assert_UncopyableObject_StaysUncopyable(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void StorageControls_DefaultToTrue() => ObjectConformanceTestCases.Assert_StorageControls_DefaultToTrue(_backend);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.RefusedKeyPairs), MemberType = typeof(ObjectConformanceTestCases))]
    public void RefusedKeyPairGeneration_LeavesNothing(string refused) => ObjectConformanceTestCases.Assert_RefusedKeyPairGeneration_LeavesNothing(_backend, refused);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.MismatchedCurve25519Keys), MemberType = typeof(ObjectConformanceTestCases))]
    // opencryptoki does not check the length of an Edwards or Montgomery CKA_VALUE: OpenSSL fails to build the key
    // from 31 or 33 bytes, and that failure comes back as CKR_FUNCTION_FAILED (fill_ec_key_from_privkey,
    // usr/lib/common/mech_openssl.c). The key is still refused and nothing is created.
    public void MismatchedCurve25519Key_IsRefused(string row) => ObjectConformanceTestCases.Assert_MismatchedCurve25519Key_IsRefused(_backend, row,
        alsoAccepted: row.EndsWith("bytes", StringComparison.Ordinal) ? [CKR.CKR_FUNCTION_FAILED] : null);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.SensitiveCopyGuesses), MemberType = typeof(ObjectConformanceTestCases))]
    public void CopyWithAGuess_AnswersTheSameForARightAndAWrongGuess(string guess) => ObjectConformanceTestCases.Assert_CopyWithAGuess_AnswersTheSameForARightAndAWrongGuess(_backend, guess);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void SearchBySensitiveValue_AnswersAsRecorded() => ObjectConformanceTestCases.Assert_SearchBySensitiveValue_AnswersAsRecorded(_backend, matchesTheSensitiveValue: true);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void UniqueId_OfDerivedAndUnwrappedKeys_IsTheirOwn() => ObjectConformanceTestCases.Assert_UniqueId_OfDerivedAndUnwrappedKeys_IsTheirOwn(_backend);

    [Theory(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    [MemberData(nameof(ObjectConformanceTestCases.PublicKeyCopies), MemberType = typeof(ObjectConformanceTestCases))]
    public void PublicKeyCopy_PlainAndRestated_AnswerAsRecorded(string row) => ObjectConformanceTestCases.Assert_PublicKeyCopy_PlainAndRestated_AnswerAsRecorded(_backend, row);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void EcPublicKey_IsFoundByItsParamsAndByItsPoint() => ObjectConformanceTestCases.Assert_EcPublicKey_IsFoundByItsParamsAndByItsPoint(_backend);
}
