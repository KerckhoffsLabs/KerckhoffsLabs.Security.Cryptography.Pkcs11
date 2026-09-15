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
}
