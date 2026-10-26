using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationContract over BouncyHsm — thin wrapper over <see cref="OperationContractTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class OperationContractTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void CbcPad_MultipartDecrypt_MatchesBcl() => OperationContractTestCases.Assert_CbcPad_MultipartDecrypt_MatchesBcl(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(OperationContractTestCases.BufferTooSmallOperations), MemberType = typeof(OperationContractTestCases))]
    public void SingleCall_BufferTooSmall_ReportsAUsableLength(string operation)
        => OperationContractTestCases.Assert_SingleCall_BufferTooSmall_ReportsAUsableLength(_backend, operation);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(OperationContractTestCases.FailingOperations), MemberType = typeof(OperationContractTestCases))]
    public void Operation_AfterAnError_TheSessionStaysUsable(string failure)
        => OperationContractTestCases.Assert_Operation_AfterAnError_TheSessionStaysUsable(_backend, failure);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Session_ClosedMidOperation_LeavesTheNextSessionClean() => OperationContractTestCases.Assert_Session_ClosedMidOperation_LeavesTheNextSessionClean(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(OperationContractTestCases.MultipartDigests), MemberType = typeof(OperationContractTestCases))]
    public void Digest_Multipart_MatchesSinglePart(CKM mechanism) => OperationContractTestCases.Assert_Digest_Multipart_MatchesSinglePart(_backend, mechanism);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(OperationContractTestCases.MultipartHmacs), MemberType = typeof(OperationContractTestCases))]
    public void Hmac_Multipart_MatchesBcl(CKM mechanism) => OperationContractTestCases.Assert_Hmac_Multipart_MatchesBcl(_backend, mechanism);
}
