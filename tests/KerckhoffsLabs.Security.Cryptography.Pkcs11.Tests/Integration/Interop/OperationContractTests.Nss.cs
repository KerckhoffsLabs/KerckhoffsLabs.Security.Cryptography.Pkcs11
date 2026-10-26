using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationContract over NSS softoken — thin wrapper over <see cref="OperationContractTestCases"/>.</summary>
[Collection("Nss")]
public sealed class OperationContractTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void CbcPad_MultipartDecrypt_MatchesBcl() => OperationContractTestCases.Assert_CbcPad_MultipartDecrypt_MatchesBcl(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationContractTestCases.BufferTooSmallOperations), MemberType = typeof(OperationContractTestCases))]
    public void SingleCall_BufferTooSmall_ReportsAUsableLength(string operation)
    {
        if (operation == "RSA-OAEP-SHA256")
            _backend.RequireSoftoken(3, 52, "NSS 3.51 answers an RSA-OAEP C_Decrypt into a 1-byte buffer with CKR_DEVICE_ERROR, not CKR_BUFFER_TOO_SMALL");
        OperationContractTestCases.Assert_SingleCall_BufferTooSmall_ReportsAUsableLength(_backend, operation);
    }

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationContractTestCases.FailingOperations), MemberType = typeof(OperationContractTestCases))]
    public void Operation_AfterAnError_TheSessionStaysUsable(string failure)
    {
        if (failure == "AES-CBC partial block")
            _backend.RequireSoftoken(3, 52, "NSS 3.51 keeps a multi-part decryption active after C_DecryptFinal refuses a partial block, and has no C_SessionCancel (v3.0) for the library to end it with");
        if (failure == "HMAC wrong MAC")
            _backend.RequireSoftoken(3, 52, "NSS 3.51 answers a wrong HMAC at C_VerifyFinal with CKR_ARGUMENTS_BAD, not CKR_SIGNATURE_INVALID");
        OperationContractTestCases.Assert_Operation_AfterAnError_TheSessionStaysUsable(_backend, failure);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Session_ClosedMidOperation_LeavesTheNextSessionClean() => OperationContractTestCases.Assert_Session_ClosedMidOperation_LeavesTheNextSessionClean(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationContractTestCases.MultipartDigests), MemberType = typeof(OperationContractTestCases))]
    public void Digest_Multipart_MatchesSinglePart(CKM mechanism) => OperationContractTestCases.Assert_Digest_Multipart_MatchesSinglePart(_backend, mechanism);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(OperationContractTestCases.MultipartHmacs), MemberType = typeof(OperationContractTestCases))]
    public void Hmac_Multipart_MatchesBcl(CKM mechanism) => OperationContractTestCases.Assert_Hmac_Multipart_MatchesBcl(_backend, mechanism);
}
