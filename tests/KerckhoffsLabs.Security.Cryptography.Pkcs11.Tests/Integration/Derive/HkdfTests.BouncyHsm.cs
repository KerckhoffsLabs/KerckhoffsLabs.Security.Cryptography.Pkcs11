using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>CKM_HKDF_DERIVE over BouncyHsm — thin wrapper over <see cref="HkdfTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class HkdfTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ExtractAndExpand_MatchesBcl() => HkdfTestCases.Assert_ExtractAndExpand_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ExpandOnly_MatchesBcl() => HkdfTestCases.Assert_ExpandOnly_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ExtractOnly_MatchesBcl() => HkdfTestCases.Assert_ExtractOnly_MatchesBcl(_backend);

    // Sign-probe variants: same derivations, verified without reading CKA_VALUE — see
    // HkdfTestCases's class doc comment for why this is a useful cross-check on its own.

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ExtractAndExpand_MatchesBclViaSignProbe() => HkdfTestCases.Assert_ExtractAndExpand_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ExpandOnly_MatchesBclViaSignProbe() => HkdfTestCases.Assert_ExpandOnly_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ExtractOnly_MatchesBclViaSignProbe() => HkdfTestCases.Assert_ExtractOnly_MatchesBclViaSignProbe(_backend);

    [Theory(SkipUnless = nameof(BouncyHsmBackendFixture.HkdfParameterRefusalAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "BouncyHsm refuses an HKDF output past RFC 5869's limit with CKR_GENERAL_ERROR or cuts it, and a salt key with CKR_OBJECT_HANDLE_INVALID")]
    [MemberData(nameof(HkdfTestCases.HkdfParameterFaults), MemberType = typeof(HkdfTestCases))]
    public void Hkdf_ParameterOutOfRange_IsRefused(string fault) => HkdfTestCases.Assert_Hkdf_ParameterOutOfRange_IsRefused(_backend, fault);
}
