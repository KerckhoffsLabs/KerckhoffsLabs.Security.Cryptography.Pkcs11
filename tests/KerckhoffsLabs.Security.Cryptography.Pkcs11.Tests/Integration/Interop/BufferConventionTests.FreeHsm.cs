using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>BufferConvention over FreeHSM — thin wrapper over <see cref="BufferConventionTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class BufferConventionTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.MultipartFinals), MemberType = typeof(BufferConventionTestCases))]
    public void MultipartFinal_BufferTooSmall_KeepsTheOperation(string operation)
    {
        if (operation == "AES-GCM decrypt")
            Assert.Skip("FreeHSM answers a C_DecryptFinal into a buffer too small for the AES-GCM plaintext with CKR_ENCRYPTED_DATA_INVALID.");
        BufferConventionTestCases.Assert_MultipartFinal_BufferTooSmall_KeepsTheOperation(_backend, operation);
    }

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.EmptyEncryptions), MemberType = typeof(BufferConventionTestCases))]
    public void EncryptFinal_WithNoUpdate_IsTheEmptyMessage(string mode) => BufferConventionTestCases.Assert_EncryptFinal_WithNoUpdate_IsTheEmptyMessage(_backend, mode);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Digest_EmptyStream_IsTheHashOfNothing() => BufferConventionTestCases.Assert_Digest_EmptyStream_IsTheHashOfNothing(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void HmacVerify_EmptyStream_IsTheMacOfNothing() => BufferConventionTestCases.Assert_HmacVerify_EmptyStream_IsTheMacOfNothing(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.StreamPieceLengths), MemberType = typeof(BufferConventionTestCases))]
    public void StreamCbc_AnyPieceLength_MatchesBcl(int bufferLength) => BufferConventionTestCases.Assert_StreamCbc_AnyPieceLength_MatchesBcl(_backend, bufferLength);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void GetAttributeValue_ShortBuffer_IsUnavailableInformation() => BufferConventionTestCases.Assert_GetAttributeValue_ShortBuffer_IsUnavailableInformation(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.SearchResultCounts), MemberType = typeof(BufferConventionTestCases))]
    public void FindAllObjects_AcrossPages_ReturnsEveryObjectOnce(int count) => BufferConventionTestCases.Assert_FindAllObjects_AcrossPages_ReturnsEveryObjectOnce(_backend, count);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.LargeRandomLengths), MemberType = typeof(BufferConventionTestCases))]
    public void GenerateRandom_Large_FillsTheBuffer(int length) => BufferConventionTestCases.Assert_GenerateRandom_Large_FillsTheBuffer(_backend, length);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void SeedRandom_IsTakenOrRefusedCleanly() => BufferConventionTestCases.Assert_SeedRandom_IsTakenOrRefusedCleanly(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.BoundaryDigests), MemberType = typeof(BufferConventionTestCases))]
    public void Digest_AroundBlockBoundaries_MatchesBcl(CKM mechanism) => BufferConventionTestCases.Assert_Digest_AroundBlockBoundaries_MatchesBcl(_backend, mechanism);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.CbcPadWholeBlockLengths), MemberType = typeof(BufferConventionTestCases))]
    public void CbcPadEncrypt_LengthQuery_CoversThePaddingBlock(int length) => BufferConventionTestCases.Assert_CbcPadEncrypt_LengthQuery_CoversThePaddingBlock(_backend, length);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Digest_LengthQuery_KeepsTheOperation() => BufferConventionTestCases.Assert_Digest_LengthQuery_KeepsTheOperation(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.ShortBufferAttributes), MemberType = typeof(BufferConventionTestCases))]
    public void GetAttributeValue_ShortBuffer_WritesNothingPastIt(string attribute)
    {
        if (!attribute.StartsWith("CKA_LABEL", StringComparison.Ordinal) && !FreeHsmBackendFixture.FreeHsmReportsAShortBufferForKeyAttributes)
            Assert.Skip("FreeHSM answers a public key attribute read into a buffer too small with CKR_OK");
        BufferConventionTestCases.Assert_GetAttributeValue_ShortBuffer_WritesNothingPastIt(_backend, attribute);
    }

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.LargeBufferAttributes), MemberType = typeof(BufferConventionTestCases))]
    public void GetAttributeValue_LargeBuffer_SetsTheExactLength(string attribute) => BufferConventionTestCases.Assert_GetAttributeValue_LargeBuffer_SetsTheExactLength(_backend, attribute);
}
