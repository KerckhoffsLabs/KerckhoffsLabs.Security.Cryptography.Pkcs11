using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationState over BouncyHsm — thin wrapper over <see cref="OperationStateTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class OperationStateTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.CallsWithoutInit), MemberType = typeof(OperationStateTestCases))]
    public void CallWithoutInit_IsOperationNotInitialized(string call) => OperationStateTestCases.Assert_CallWithoutInit_IsOperationNotInitialized(_backend, call);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void UpdateAfterFinal_IsOperationNotInitialized() => OperationStateTestCases.Assert_UpdateAfterFinal_IsOperationNotInitialized(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Operation_BelongsToItsSession() => OperationStateTestCases.Assert_Operation_BelongsToItsSession(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.SecondInits), MemberType = typeof(OperationStateTestCases))]
    public void SecondInit_IsOperationActive(string operation) => OperationStateTestCases.Assert_SecondInit_IsOperationActive(_backend, operation);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.MechanismsOfTheWrongKind), MemberType = typeof(OperationStateTestCases))]
    public void MechanismOfTheWrongKind_IsMechanismInvalid(string misuse)
    {
        // BouncyHsm answers C_GenerateKey with CKM_SHA256 with CKR_ARGUMENTS_BAD.
        OperationStateTestCases.Assert_MechanismOfTheWrongKind_IsMechanismInvalid(_backend, misuse, [CKR.CKR_ARGUMENTS_BAD]);
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.KeysOfTheWrongType), MemberType = typeof(OperationStateTestCases))]
    public void KeyOfTheWrongType_IsRefused(string misuse) => OperationStateTestCases.Assert_KeyOfTheWrongType_IsRefused(_backend, misuse);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.UsesOfADestroyedKey), MemberType = typeof(OperationStateTestCases))]
    public void DestroyedKey_IsRefused(string use) => OperationStateTestCases.Assert_DestroyedKey_IsRefused(_backend, use);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.PartialBlockEncryptions), MemberType = typeof(OperationStateTestCases))]
    public void PartialBlock_Encrypt_IsDataLenRange(CKM mechanism, int length)
    {
        // BouncyHsm keeps the encryption active after refusing a partial block.
        OperationStateTestCases.Assert_PartialBlock_Encrypt_IsDataLenRange(_backend, mechanism, length, keepsTheOperation: true);
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.PartialBlockDecryptions), MemberType = typeof(OperationStateTestCases))]
    public void PartialBlock_Decrypt_IsEncryptedDataLenRange(CKM mechanism, int length)
    {
        // BouncyHsm keeps the decryption active after refusing a partial block.
        OperationStateTestCases.Assert_PartialBlock_Decrypt_IsEncryptedDataLenRange(_backend, mechanism, length, keepsTheOperation: true);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void LegacyParallelFunctions_AreNotParallel() => OperationStateTestCases.Assert_LegacyParallelFunctions_AreNotParallel(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SessionCancel_EndsTheOperationsItNames() => OperationStateTestCases.Assert_SessionCancel_EndsTheOperationsItNames(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(OperationStateTestCases.WrongLengthSignatures), MemberType = typeof(OperationStateTestCases))]
    public void Verify_WrongLengthSignature_EndsTheOperation(string shape) => OperationStateTestCases.Assert_Verify_WrongLengthSignature_EndsTheOperation(_backend, shape);
}
