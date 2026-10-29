using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>BufferConvention over Craton HSM — thin wrapper over <see cref="BufferConventionTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class BufferConventionTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.MultipartFinals), MemberType = typeof(BufferConventionTestCases))]
    public void MultipartFinal_BufferTooSmall_KeepsTheOperation(string operation)
    {
        if (operation.StartsWith("AES-GCM", StringComparison.Ordinal))
            Assert.Skip("Craton HSM runs AES-GCM single-part only, so it has no multi-part final.");
        BufferConventionTestCases.Assert_MultipartFinal_BufferTooSmall_KeepsTheOperation(_backend, operation);
    }

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.EmptyEncryptions), MemberType = typeof(BufferConventionTestCases))]
    public void EncryptFinal_WithNoUpdate_IsTheEmptyMessage(string mode)
    {
        if (mode == "AES-GCM")
            Assert.Skip("Craton HSM runs AES-GCM single-part only, so it has no final.");
        // Craton HSM refuses an empty AES-CBC message at C_EncryptFinal with CKR_DATA_LEN_RANGE.
        BufferConventionTestCases.Assert_EncryptFinal_WithNoUpdate_IsTheEmptyMessage(_backend, mode, refusal: CKR.CKR_DATA_LEN_RANGE);
    }

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Digest_EmptyStream_IsTheHashOfNothing() => BufferConventionTestCases.Assert_Digest_EmptyStream_IsTheHashOfNothing(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void HmacVerify_EmptyStream_IsTheMacOfNothing() => BufferConventionTestCases.Assert_HmacVerify_EmptyStream_IsTheMacOfNothing(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.StreamPieceLengths), MemberType = typeof(BufferConventionTestCases))]
    public void StreamCbc_AnyPieceLength_MatchesBcl(int bufferLength) => BufferConventionTestCases.Assert_StreamCbc_AnyPieceLength_MatchesBcl(_backend, bufferLength);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void GetAttributeValue_ShortBuffer_IsUnavailableInformation()
    {
        // Craton HSM sets ulValueLen to the length the attribute needs, not to CK_UNAVAILABLE_INFORMATION.
        BufferConventionTestCases.Assert_GetAttributeValue_ShortBuffer_IsUnavailableInformation(_backend, reportsTheNeededLength: true);
    }

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.SearchResultCounts), MemberType = typeof(BufferConventionTestCases))]
    public void FindAllObjects_AcrossPages_ReturnsEveryObjectOnce(int count) => BufferConventionTestCases.Assert_FindAllObjects_AcrossPages_ReturnsEveryObjectOnce(_backend, count);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.LargeRandomLengths), MemberType = typeof(BufferConventionTestCases))]
    public void GenerateRandom_Large_FillsTheBuffer(int length) => BufferConventionTestCases.Assert_GenerateRandom_Large_FillsTheBuffer(_backend, length);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SeedRandom_IsTakenOrRefusedCleanly() => BufferConventionTestCases.Assert_SeedRandom_IsTakenOrRefusedCleanly(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(BufferConventionTestCases.BoundaryDigests), MemberType = typeof(BufferConventionTestCases))]
    public void Digest_AroundBlockBoundaries_MatchesBcl(CKM mechanism) => BufferConventionTestCases.Assert_Digest_AroundBlockBoundaries_MatchesBcl(_backend, mechanism);
}
