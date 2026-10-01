using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// Modules disagree on how they report a failed AEAD tag check, so the AEAD adapters accept all three
// codes seen in practice as the BCL's AuthenticationTagMismatchException. Everything else must stay a
// Pkcs11Exception: reporting a session or device failure as tampering would mislead the caller.
public sealed class AeadDecryptionTests
{
    [Theory]
    [InlineData(CKR.CKR_AEAD_DECRYPT_FAILED)]
    [InlineData(CKR.CKR_ENCRYPTED_DATA_INVALID)]
    [InlineData(CKR.CKR_SIGNATURE_INVALID)]
    public void IsTagMismatch_TagFailureCode_IsTrue(CKR returnValue) =>
        Assert.True(AeadDecryption.IsTagMismatch(returnValue));

    [Theory]
    [InlineData(CKR.CKR_OK)]
    [InlineData(CKR.CKR_KEY_HANDLE_INVALID)]
    [InlineData(CKR.CKR_KEY_FUNCTION_NOT_PERMITTED)]
    [InlineData(CKR.CKR_FUNCTION_NOT_SUPPORTED)]
    [InlineData(CKR.CKR_ENCRYPTED_DATA_LEN_RANGE)]
    [InlineData(CKR.CKR_DEVICE_ERROR)]
    [InlineData(CKR.CKR_SESSION_HANDLE_INVALID)]
    public void IsTagMismatch_OtherCode_IsFalse(CKR returnValue) =>
        Assert.False(AeadDecryption.IsTagMismatch(returnValue));
}
