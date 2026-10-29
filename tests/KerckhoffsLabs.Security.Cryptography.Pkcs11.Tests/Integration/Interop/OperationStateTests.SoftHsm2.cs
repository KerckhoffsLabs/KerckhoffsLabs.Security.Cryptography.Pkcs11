using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationState over SoftHSM2 — thin wrapper over <see cref="OperationStateTestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class OperationStateTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.CallsWithoutInit), MemberType = typeof(OperationStateTestCases))]
    public void CallWithoutInit_IsOperationNotInitialized(string call) => OperationStateTestCases.Assert_CallWithoutInit_IsOperationNotInitialized(_backend, call);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void UpdateAfterFinal_IsOperationNotInitialized() => OperationStateTestCases.Assert_UpdateAfterFinal_IsOperationNotInitialized(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Operation_BelongsToItsSession() => OperationStateTestCases.Assert_Operation_BelongsToItsSession(_backend);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.SecondInits), MemberType = typeof(OperationStateTestCases))]
    public void SecondInit_IsOperationActive(string operation) => OperationStateTestCases.Assert_SecondInit_IsOperationActive(_backend, operation);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.MechanismsOfTheWrongKind), MemberType = typeof(OperationStateTestCases))]
    public void MechanismOfTheWrongKind_IsMechanismInvalid(string misuse) => OperationStateTestCases.Assert_MechanismOfTheWrongKind_IsMechanismInvalid(_backend, misuse);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.KeysOfTheWrongType), MemberType = typeof(OperationStateTestCases))]
    public void KeyOfTheWrongType_IsRefused(string misuse)
    {
        if (SoftHsmBackendFixture.IsV240Leg && misuse.StartsWith("ECDSA", StringComparison.Ordinal))
            Assert.Skip("SoftHSM 2.5 accepts C_SignInit and C_VerifyInit with CKM_ECDSA and an AES key.");
        // SoftHSM 2.5 answers AES-CBC with an EC public key with CKR_MECHANISM_INVALID.
        OperationStateTestCases.Assert_KeyOfTheWrongType_IsRefused(_backend, misuse,
            SoftHsmBackendFixture.IsV240Leg ? [CKR.CKR_MECHANISM_INVALID] : null);
    }

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.UsesOfADestroyedKey), MemberType = typeof(OperationStateTestCases))]
    public void DestroyedKey_IsRefused(string use) => OperationStateTestCases.Assert_DestroyedKey_IsRefused(_backend, use);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.PartialBlockEncryptions), MemberType = typeof(OperationStateTestCases))]
    public void PartialBlock_Encrypt_IsDataLenRange(CKM mechanism, int length) => OperationStateTestCases.Assert_PartialBlock_Encrypt_IsDataLenRange(_backend, mechanism, length);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.PartialBlockDecryptions), MemberType = typeof(OperationStateTestCases))]
    public void PartialBlock_Decrypt_IsEncryptedDataLenRange(CKM mechanism, int length) => OperationStateTestCases.Assert_PartialBlock_Decrypt_IsEncryptedDataLenRange(_backend, mechanism, length);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void LegacyParallelFunctions_AreNotParallel() => OperationStateTestCases.Assert_LegacyParallelFunctions_AreNotParallel(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void SessionCancel_EndsTheOperationsItNames() => OperationStateTestCases.Assert_SessionCancel_EndsTheOperationsItNames(_backend);

    [Theory(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.WrongLengthSignatures), MemberType = typeof(OperationStateTestCases))]
    public void Verify_WrongLengthSignature_EndsTheOperation(string shape) => OperationStateTestCases.Assert_Verify_WrongLengthSignature_EndsTheOperation(_backend, shape);
}
