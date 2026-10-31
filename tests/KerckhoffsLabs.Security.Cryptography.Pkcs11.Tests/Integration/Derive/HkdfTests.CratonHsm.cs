using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>CKM_HKDF_DERIVE over Craton HSM — thin wrapper over <see cref="HkdfTestCases"/>.</summary>
[Collection("CratonHsm")]
public sealed class HkdfTests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ExtractAndExpand_MatchesBcl() => HkdfTestCases.Assert_ExtractAndExpand_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ExpandOnly_MatchesBcl() => HkdfTestCases.Assert_ExpandOnly_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ExtractOnly_MatchesBcl() => HkdfTestCases.Assert_ExtractOnly_MatchesBcl(_backend);

    // Sign-probe variants: same derivations, verified without reading CKA_VALUE — see
    // HkdfTestCases's class doc comment for why this is a useful cross-check on its own.

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ExtractAndExpand_MatchesBclViaSignProbe() => HkdfTestCases.Assert_ExtractAndExpand_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ExpandOnly_MatchesBclViaSignProbe() => HkdfTestCases.Assert_ExpandOnly_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void ExtractOnly_MatchesBclViaSignProbe() => HkdfTestCases.Assert_ExtractOnly_MatchesBclViaSignProbe(_backend);

    [Theory(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    [MemberData(nameof(HkdfTestCases.HkdfParameterFaults), MemberType = typeof(HkdfTestCases))]
    public void Hkdf_ParameterOutOfRange_IsRefused(string fault) => HkdfTestCases.Assert_Hkdf_ParameterOutOfRange_IsRefused(_backend, fault);
}
