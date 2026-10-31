using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationState over NSS softoken — thin wrapper over <see cref="OperationStateTestCases"/>.</summary>
[Collection("Nss")]
public sealed class OperationStateTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationStateTestCases.CallsWithoutInit), MemberType = typeof(OperationStateTestCases))]
    public void CallWithoutInit_IsOperationNotInitialized(string call)
    {
        // NSS softoken answers C_FindObjects and C_FindObjectsFinal with no search active with CKR_OK.
        CKR expected = call is "C_FindObjects" or "C_FindObjectsFinal" ? CKR.CKR_OK : CKR.CKR_OPERATION_NOT_INITIALIZED;
        OperationStateTestCases.Assert_CallWithoutInit_IsOperationNotInitialized(_backend, call, expected);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void UpdateAfterFinal_IsOperationNotInitialized() => OperationStateTestCases.Assert_UpdateAfterFinal_IsOperationNotInitialized(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Operation_BelongsToItsSession() => OperationStateTestCases.Assert_Operation_BelongsToItsSession(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationStateTestCases.SecondInits), MemberType = typeof(OperationStateTestCases))]
    public void SecondInit_IsOperationActive(string operation)
    {
        // NSS softoken starts a new search on a second C_FindObjectsInit instead of refusing it.
        CKR expected = operation == "FindObjects" ? CKR.CKR_OK : CKR.CKR_OPERATION_ACTIVE;
        OperationStateTestCases.Assert_SecondInit_IsOperationActive(_backend, operation, expected);
    }

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationStateTestCases.MechanismsOfTheWrongKind), MemberType = typeof(OperationStateTestCases))]
    public void MechanismOfTheWrongKind_IsMechanismInvalid(string misuse)
    {
        if (misuse == "generate a key with CKM_SHA256")
            _backend.RequireSoftoken(3, 52, "NSS 3.51 crashes in C_GenerateKey with a digest mechanism");
        // NSS softoken answers C_SignInit with CKM_SHA256 and an AES key with CKR_KEY_TYPE_INCONSISTENT.
        OperationStateTestCases.Assert_MechanismOfTheWrongKind_IsMechanismInvalid(_backend, misuse, [CKR.CKR_KEY_TYPE_INCONSISTENT]);
    }

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationStateTestCases.KeysOfTheWrongType), MemberType = typeof(OperationStateTestCases))]
    public void KeyOfTheWrongType_IsRefused(string misuse)
    {
        if (misuse == "HKDF derive from an EC private key" && !NssBackendFixture.NssChecksTheHkdfBaseKeyType)
            Assert.Skip("NSS derives HKDF from an EC private key");
        OperationStateTestCases.Assert_KeyOfTheWrongType_IsRefused(_backend, misuse);
    }

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationStateTestCases.UsesOfADestroyedKey), MemberType = typeof(OperationStateTestCases))]
    public void DestroyedKey_IsRefused(string use) => OperationStateTestCases.Assert_DestroyedKey_IsRefused(_backend, use);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationStateTestCases.PartialBlockEncryptions), MemberType = typeof(OperationStateTestCases))]
    public void PartialBlock_Encrypt_IsDataLenRange(CKM mechanism, int length) => OperationStateTestCases.Assert_PartialBlock_Encrypt_IsDataLenRange(_backend, mechanism, length);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationStateTestCases.PartialBlockDecryptions), MemberType = typeof(OperationStateTestCases))]
    public void PartialBlock_Decrypt_IsEncryptedDataLenRange(CKM mechanism, int length)
    {
        // NSS softoken answers a partial ciphertext block with CKR_DATA_LEN_RANGE.
        OperationStateTestCases.Assert_PartialBlock_Decrypt_IsEncryptedDataLenRange(_backend, mechanism, length, CKR.CKR_DATA_LEN_RANGE);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void LegacyParallelFunctions_AreNotParallel() => OperationStateTestCases.Assert_LegacyParallelFunctions_AreNotParallel(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void SessionCancel_EndsTheOperationsItNames() => OperationStateTestCases.Assert_SessionCancel_EndsTheOperationsItNames(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationStateTestCases.WrongLengthSignatures), MemberType = typeof(OperationStateTestCases))]
    public void Verify_WrongLengthSignature_EndsTheOperation(string shape) => OperationStateTestCases.Assert_Verify_WrongLengthSignature_EndsTheOperation(_backend, shape);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationStateTestCases.NonKeyObjectsAsKeys), MemberType = typeof(OperationStateTestCases))]
    public void NonKeyObject_IsRefusedAsAKey(string misuse)
    {
        if ((misuse.StartsWith("C_WrapKey", StringComparison.Ordinal) || misuse.StartsWith("C_UnwrapKey", StringComparison.Ordinal)) && !NssBackendFixture.NssNamesTheWrappingKeyInARefusal)
            Assert.Skip("NSS refuses a wrapping key that is no key with CKR_KEY_TYPE_INCONSISTENT");
        OperationStateTestCases.Assert_NonKeyObject_IsRefusedAsAKey(_backend, misuse);
    }

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationStateTestCases.OperationsWhoseKeyIsDestroyed), MemberType = typeof(OperationStateTestCases))]
    public void KeyDestroyedMidOperation_SessionStaysUsable(string operation)
    {
        if (operation == "AES-GCM encrypt")
            Assert.Skip("NSS softoken runs classic AES-GCM single-part only, so it has no multi-part encryption.");
        OperationStateTestCases.Assert_KeyDestroyedMidOperation_SessionStaysUsable(_backend, operation);
    }

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationStateTestCases.ShortCiphertexts), MemberType = typeof(OperationStateTestCases))]
    public void ShortCiphertext_Decrypt_IsRefused(string ciphertext)
    {
        if (!ciphertext.StartsWith("AES-CBC-PAD", StringComparison.Ordinal) && !NssBackendFixture.NssRefusesAShortCiphertextAsEncryptedDataLenRange)
            Assert.Skip("NSS refuses an AES-GCM or key-wrap ciphertext of a wrong length with CKR_DATA_LEN_RANGE");
        OperationStateTestCases.Assert_ShortCiphertext_Decrypt_IsRefused(_backend, ciphertext);
    }
}
