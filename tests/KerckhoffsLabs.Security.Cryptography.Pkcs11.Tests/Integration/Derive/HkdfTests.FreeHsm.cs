using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>CKM_HKDF_DERIVE over FreeHSM — thin wrapper over <see cref="HkdfTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class HkdfTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void ExtractAndExpand_MatchesBcl() => HkdfTestCases.Assert_ExtractAndExpand_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void ExpandOnly_MatchesBcl() => HkdfTestCases.Assert_ExpandOnly_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void ExtractOnly_MatchesBcl() => HkdfTestCases.Assert_ExtractOnly_MatchesBcl(_backend);

    // Sign-probe variants: same derivations, verified without reading CKA_VALUE — see
    // HkdfTestCases's class doc comment for why this is a useful cross-check on its own.

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void ExtractAndExpand_MatchesBclViaSignProbe() => HkdfTestCases.Assert_ExtractAndExpand_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void ExpandOnly_MatchesBclViaSignProbe() => HkdfTestCases.Assert_ExpandOnly_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void ExtractOnly_MatchesBclViaSignProbe() => HkdfTestCases.Assert_ExtractOnly_MatchesBclViaSignProbe(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(HkdfTestCases.HkdfParameterFaults), MemberType = typeof(HkdfTestCases))]
    public void Hkdf_ParameterOutOfRange_IsRefused(string fault) => HkdfTestCases.Assert_Hkdf_ParameterOutOfRange_IsRefused(_backend, fault);
}
