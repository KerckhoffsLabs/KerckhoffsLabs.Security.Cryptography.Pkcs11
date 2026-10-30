using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>CKM_HKDF_DERIVE over NSS — thin wrapper over <see cref="HkdfTestCases"/>.</summary>
[Collection("Nss")]
public sealed class HkdfTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    // NSS refuses to derive a readable (extractable) key (see SP800108HmacCounterKdfPkcs11Tests.Nss.cs
    // for the same, already-documented limitation), so these read-back-and-compare cases are gated on
    // ExtractableDeriveAvailable rather than plain NssAvailable.

    [Fact(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    public void ExtractAndExpand_MatchesBcl() => HkdfTestCases.Assert_ExtractAndExpand_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    public void ExpandOnly_MatchesBcl() => HkdfTestCases.Assert_ExpandOnly_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    public void ExtractOnly_MatchesBcl() => HkdfTestCases.Assert_ExtractOnly_MatchesBcl(_backend);

    // Sign-probe variants: prove the same derivations without reading CKA_VALUE, so these run on
    // NSS today instead of waiting on ExtractableDeriveAvailable.

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExtractAndExpand_MatchesBclViaSignProbe() => HkdfTestCases.Assert_ExtractAndExpand_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExpandOnly_MatchesBclViaSignProbe() => HkdfTestCases.Assert_ExpandOnly_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExtractOnly_MatchesBclViaSignProbe() => HkdfTestCases.Assert_ExtractOnly_MatchesBclViaSignProbe(_backend);

    [Theory(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    [MemberData(nameof(HkdfTestCases.HkdfParameterFaults), MemberType = typeof(HkdfTestCases))]
    public void Hkdf_ParameterOutOfRange_IsRefused(string fault)
    {
        if (fault == "CKA_VALUE_LEN 2^32 + 1" && !NssBackendFixture.NssRefusesAnHkdfValueLenPastTheLimit)
            Assert.Skip("NSS narrows an HKDF CKA_VALUE_LEN of 2^32 + 1 and derives");
        HkdfTestCases.Assert_Hkdf_ParameterOutOfRange_IsRefused(_backend, fault);
    }
}
