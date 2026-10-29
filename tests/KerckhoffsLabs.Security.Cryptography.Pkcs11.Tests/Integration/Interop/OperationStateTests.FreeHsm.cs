using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationState over FreeHSM — thin wrapper over <see cref="OperationStateTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class OperationStateTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.CallsWithoutInit), MemberType = typeof(OperationStateTestCases))]
    public void CallWithoutInit_IsOperationNotInitialized(string call) => OperationStateTestCases.Assert_CallWithoutInit_IsOperationNotInitialized(_backend, call);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void UpdateAfterFinal_IsOperationNotInitialized() => OperationStateTestCases.Assert_UpdateAfterFinal_IsOperationNotInitialized(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Operation_BelongsToItsSession() => OperationStateTestCases.Assert_Operation_BelongsToItsSession(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.SecondInits), MemberType = typeof(OperationStateTestCases))]
    public void SecondInit_IsOperationActive(string operation) => OperationStateTestCases.Assert_SecondInit_IsOperationActive(_backend, operation);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.MechanismsOfTheWrongKind), MemberType = typeof(OperationStateTestCases))]
    public void MechanismOfTheWrongKind_IsMechanismInvalid(string misuse) => OperationStateTestCases.Assert_MechanismOfTheWrongKind_IsMechanismInvalid(_backend, misuse);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.KeysOfTheWrongType), MemberType = typeof(OperationStateTestCases))]
    public void KeyOfTheWrongType_IsRefused(string misuse) => OperationStateTestCases.Assert_KeyOfTheWrongType_IsRefused(_backend, misuse);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.UsesOfADestroyedKey), MemberType = typeof(OperationStateTestCases))]
    public void DestroyedKey_IsRefused(string use)
    {
        // FreeHSM answers C_DestroyObject on a destroyed key with CKR_KEY_HANDLE_INVALID.
        OperationStateTestCases.Assert_DestroyedKey_IsRefused(_backend, use, use == "C_DestroyObject" ? CKR.CKR_KEY_HANDLE_INVALID : null);
    }

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.PartialBlockEncryptions), MemberType = typeof(OperationStateTestCases))]
    public void PartialBlock_Encrypt_IsDataLenRange(CKM mechanism, int length)
    {
        // FreeHSM answers a partial plaintext block with CKR_FUNCTION_FAILED.
        OperationStateTestCases.Assert_PartialBlock_Encrypt_IsDataLenRange(_backend, mechanism, length, CKR.CKR_FUNCTION_FAILED);
    }

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.PartialBlockDecryptions), MemberType = typeof(OperationStateTestCases))]
    public void PartialBlock_Decrypt_IsEncryptedDataLenRange(CKM mechanism, int length)
    {
        // FreeHSM answers a partial ciphertext block with CKR_ENCRYPTED_DATA_INVALID.
        OperationStateTestCases.Assert_PartialBlock_Decrypt_IsEncryptedDataLenRange(_backend, mechanism, length, CKR.CKR_ENCRYPTED_DATA_INVALID);
    }

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void LegacyParallelFunctions_AreNotParallel() => OperationStateTestCases.Assert_LegacyParallelFunctions_AreNotParallel(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void SessionCancel_EndsTheOperationsItNames() => OperationStateTestCases.Assert_SessionCancel_EndsTheOperationsItNames(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.WrongLengthSignatures), MemberType = typeof(OperationStateTestCases))]
    public void Verify_WrongLengthSignature_EndsTheOperation(string shape) => OperationStateTestCases.Assert_Verify_WrongLengthSignature_EndsTheOperation(_backend, shape);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.NonKeyObjectsAsKeys), MemberType = typeof(OperationStateTestCases))]
    public void NonKeyObject_IsRefusedAsAKey(string misuse) => OperationStateTestCases.Assert_NonKeyObject_IsRefusedAsAKey(_backend, misuse);
}
