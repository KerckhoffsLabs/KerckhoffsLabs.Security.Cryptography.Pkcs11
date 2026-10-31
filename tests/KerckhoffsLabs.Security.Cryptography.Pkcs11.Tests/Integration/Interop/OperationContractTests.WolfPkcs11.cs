using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>OperationContract over wolfPKCS11 — thin wrapper over <see cref="OperationContractTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class OperationContractTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void CbcPad_MultipartDecrypt_MatchesBcl() => OperationContractTestCases.Assert_CbcPad_MultipartDecrypt_MatchesBcl(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(OperationContractTestCases.BufferTooSmallOperations), MemberType = typeof(OperationContractTestCases))]
    public void SingleCall_BufferTooSmall_ReportsAUsableLength(string operation)
    {
        if (operation == "AES-CBC-PAD decrypt" && !WolfPkcs11BackendFixture.WolfPkcs11ReportsTheWholeCbcPadPlaintextLength)
            Assert.Skip("wolfPKCS11 reports too short a length for a CBC-PAD C_Decrypt into a buffer too small");
        OperationContractTestCases.Assert_SingleCall_BufferTooSmall_ReportsAUsableLength(_backend, operation);
    }

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(OperationContractTestCases.FailingOperations), MemberType = typeof(OperationContractTestCases))]
    public void Operation_AfterAnError_TheSessionStaysUsable(string failure)
        => OperationContractTestCases.Assert_Operation_AfterAnError_TheSessionStaysUsable(_backend, failure);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Session_ClosedMidOperation_LeavesTheNextSessionClean() => OperationContractTestCases.Assert_Session_ClosedMidOperation_LeavesTheNextSessionClean(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(OperationContractTestCases.MultipartDigests), MemberType = typeof(OperationContractTestCases))]
    public void Digest_Multipart_MatchesSinglePart(CKM mechanism) => OperationContractTestCases.Assert_Digest_Multipart_MatchesSinglePart(_backend, mechanism);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(OperationContractTestCases.MultipartHmacs), MemberType = typeof(OperationContractTestCases))]
    public void Hmac_Multipart_MatchesBcl(CKM mechanism) => OperationContractTestCases.Assert_Hmac_Multipart_MatchesBcl(_backend, mechanism);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(OperationContractTestCases.UnpaddedStreamModes), MemberType = typeof(OperationContractTestCases))]
    public void UnpaddedBlockMode_StreamRoundTrip_MatchesBcl(CKM mode)
    {
        if (mode == CKM.CKM_AES_ECB && !WolfPkcs11BackendFixture.WolfPkcs11DoesMultipartSignAndEcb)
            Assert.Skip("wolfPKCS11 does AES-ECB single-part only");
        OperationContractTestCases.Assert_UnpaddedBlockMode_StreamRoundTrip_MatchesBcl(_backend, mode);
    }

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void CbcPad_MultipartEncrypt_MatchesBcl() => OperationContractTestCases.Assert_CbcPad_MultipartEncrypt_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void AesCtr_LengthQuery_ReportsTheInputLength() => OperationContractTestCases.Assert_AesCtr_LengthQuery_ReportsTheInputLength(_backend);

    [Theory(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    [MemberData(nameof(OperationContractTestCases.GcmPieceLengths), MemberType = typeof(OperationContractTestCases))]
    public void AesGcm_MultipartInOddPieces_MatchesBcl(int piece) => OperationContractTestCases.Assert_AesGcm_MultipartInOddPieces_MatchesBcl(_backend, piece);
}
