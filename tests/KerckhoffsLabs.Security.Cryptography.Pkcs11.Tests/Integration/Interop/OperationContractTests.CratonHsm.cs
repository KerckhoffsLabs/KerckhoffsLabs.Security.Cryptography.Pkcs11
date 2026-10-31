using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationContract over Craton HSM — thin wrapper over <see cref="OperationContractTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class OperationContractTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void CbcPad_MultipartDecrypt_MatchesBcl() => OperationContractTestCases.Assert_CbcPad_MultipartDecrypt_MatchesBcl(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(OperationContractTestCases.BufferTooSmallOperations), MemberType = typeof(OperationContractTestCases))]
    public void SingleCall_BufferTooSmall_ReportsAUsableLength(string operation)
    {
        if (operation == "Ed448")
            Assert.Skip("Craton HSM has no Ed448.");
        OperationContractTestCases.Assert_SingleCall_BufferTooSmall_ReportsAUsableLength(_backend, operation);
    }

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(OperationContractTestCases.FailingOperations), MemberType = typeof(OperationContractTestCases))]
    public void Operation_AfterAnError_TheSessionStaysUsable(string failure)
        => OperationContractTestCases.Assert_Operation_AfterAnError_TheSessionStaysUsable(_backend, failure);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Session_ClosedMidOperation_LeavesTheNextSessionClean() => OperationContractTestCases.Assert_Session_ClosedMidOperation_LeavesTheNextSessionClean(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(OperationContractTestCases.MultipartDigests), MemberType = typeof(OperationContractTestCases))]
    public void Digest_Multipart_MatchesSinglePart(CKM mechanism) => OperationContractTestCases.Assert_Digest_Multipart_MatchesSinglePart(_backend, mechanism);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(OperationContractTestCases.MultipartHmacs), MemberType = typeof(OperationContractTestCases))]
    public void Hmac_Multipart_MatchesBcl(CKM mechanism) => OperationContractTestCases.Assert_Hmac_Multipart_MatchesBcl(_backend, mechanism);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(OperationContractTestCases.UnpaddedStreamModes), MemberType = typeof(OperationContractTestCases))]
    public void UnpaddedBlockMode_StreamRoundTrip_MatchesBcl(CKM mode) => OperationContractTestCases.Assert_UnpaddedBlockMode_StreamRoundTrip_MatchesBcl(_backend, mode);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void CbcPad_MultipartEncrypt_MatchesBcl() => OperationContractTestCases.Assert_CbcPad_MultipartEncrypt_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.AesCtrParamsAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Craton HSM takes a bare counter block, not CK_AES_CTR_PARAMS")]
    public void AesCtr_LengthQuery_ReportsTheInputLength() => OperationContractTestCases.Assert_AesCtr_LengthQuery_ReportsTheInputLength(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(OperationContractTestCases.GcmPieceLengths), MemberType = typeof(OperationContractTestCases))]
    public void AesGcm_MultipartInOddPieces_MatchesBcl(int piece) => OperationContractTestCases.Assert_AesGcm_MultipartInOddPieces_MatchesBcl(_backend, piece);
}
