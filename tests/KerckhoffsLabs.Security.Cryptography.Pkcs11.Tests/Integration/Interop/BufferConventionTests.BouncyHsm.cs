using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>BufferConvention over BouncyHsm — thin wrapper over <see cref="BufferConventionTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class BufferConventionTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.MultipartFinals), MemberType = typeof(BufferConventionTestCases))]
    public void MultipartFinal_BufferTooSmall_KeepsTheOperation(string operation) => BufferConventionTestCases.Assert_MultipartFinal_BufferTooSmall_KeepsTheOperation(_backend, operation);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.EmptyEncryptions), MemberType = typeof(BufferConventionTestCases))]
    public void EncryptFinal_WithNoUpdate_IsTheEmptyMessage(string mode)
    {
        // BouncyHsm refuses to encrypt an empty message at C_EncryptFinal with CKR_GENERAL_ERROR.
        BufferConventionTestCases.Assert_EncryptFinal_WithNoUpdate_IsTheEmptyMessage(_backend, mode, refusal: CKR.CKR_GENERAL_ERROR);
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.EmptyDigestAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm answers a digest of empty data with CKR_DATA_LEN_RANGE")]
    public void Digest_EmptyStream_IsTheHashOfNothing() => BufferConventionTestCases.Assert_Digest_EmptyStream_IsTheHashOfNothing(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void HmacVerify_EmptyStream_IsTheMacOfNothing() => BufferConventionTestCases.Assert_HmacVerify_EmptyStream_IsTheMacOfNothing(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.StreamPieceLengths), MemberType = typeof(BufferConventionTestCases))]
    public void StreamCbc_AnyPieceLength_MatchesBcl(int bufferLength) => BufferConventionTestCases.Assert_StreamCbc_AnyPieceLength_MatchesBcl(_backend, bufferLength);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void GetAttributeValue_ShortBuffer_IsUnavailableInformation()
    {
        // BouncyHsm sets ulValueLen to the length the attribute needs, not to CK_UNAVAILABLE_INFORMATION.
        BufferConventionTestCases.Assert_GetAttributeValue_ShortBuffer_IsUnavailableInformation(_backend, reportsTheNeededLength: true);
    }

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.SearchResultCounts), MemberType = typeof(BufferConventionTestCases))]
    public void FindAllObjects_AcrossPages_ReturnsEveryObjectOnce(int count) => BufferConventionTestCases.Assert_FindAllObjects_AcrossPages_ReturnsEveryObjectOnce(_backend, count);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.LargeRandomLengths), MemberType = typeof(BufferConventionTestCases))]
    public void GenerateRandom_Large_FillsTheBuffer(int length) => BufferConventionTestCases.Assert_GenerateRandom_Large_FillsTheBuffer(_backend, length);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void SeedRandom_IsTakenOrRefusedCleanly() => BufferConventionTestCases.Assert_SeedRandom_IsTakenOrRefusedCleanly(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.BoundaryDigests), MemberType = typeof(BufferConventionTestCases))]
    public void Digest_AroundBlockBoundaries_MatchesBcl(CKM mechanism) => BufferConventionTestCases.Assert_Digest_AroundBlockBoundaries_MatchesBcl(_backend, mechanism);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.CbcPadWholeBlockLengths), MemberType = typeof(BufferConventionTestCases))]
    public void CbcPadEncrypt_LengthQuery_CoversThePaddingBlock(int length) => BufferConventionTestCases.Assert_CbcPadEncrypt_LengthQuery_CoversThePaddingBlock(_backend, length);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Digest_LengthQuery_KeepsTheOperation() => BufferConventionTestCases.Assert_Digest_LengthQuery_KeepsTheOperation(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.ShortBufferAttributes), MemberType = typeof(BufferConventionTestCases))]
    public void GetAttributeValue_ShortBuffer_WritesNothingPastIt(string attribute) => BufferConventionTestCases.Assert_GetAttributeValue_ShortBuffer_WritesNothingPastIt(_backend, attribute);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.LargeBufferAttributes), MemberType = typeof(BufferConventionTestCases))]
    public void GetAttributeValue_LargeBuffer_SetsTheExactLength(string attribute) => BufferConventionTestCases.Assert_GetAttributeValue_LargeBuffer_SetsTheExactLength(_backend, attribute);
}
