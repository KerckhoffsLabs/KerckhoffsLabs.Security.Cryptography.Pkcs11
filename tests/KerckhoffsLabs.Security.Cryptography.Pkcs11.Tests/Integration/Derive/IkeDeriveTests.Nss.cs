using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>The IKE-derive family over NSS — thin wrapper over <see cref="IkeDeriveTestCases"/>.</summary>
[Collection("Nss")]
public sealed class IkeDeriveTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    // NSS refuses to derive a readable (extractable) key (see HkdfTests.Nss.cs for the same,
    // already-documented limitation), so these read-back-and-compare cases are gated on
    // ExtractableDeriveAvailable rather than plain NssAvailable.

    [Fact(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    public void IkePrf_MatchesReference() => IkeDeriveTestCases.Assert_IkePrf_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    public void Ike1Prf_MatchesReference() => IkeDeriveTestCases.Assert_Ike1Prf_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    public void Ike1ExtendedDerive_MatchesReference() => IkeDeriveTestCases.Assert_Ike1ExtendedDerive_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    public void Ike2PrfPlusDerive_MatchesReference() => IkeDeriveTestCases.Assert_Ike2PrfPlusDerive_MatchesReference(_backend);

    // Sign-probe variants: prove the same derivations without reading CKA_VALUE, so these run on
    // NSS today instead of waiting on ExtractableDeriveAvailable.

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void IkePrf_MatchesBclViaSignProbe() => IkeDeriveTestCases.Assert_IkePrf_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Ike1Prf_MatchesBclViaSignProbe() => IkeDeriveTestCases.Assert_Ike1Prf_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Ike1ExtendedDerive_MatchesBclViaSignProbe() => IkeDeriveTestCases.Assert_Ike1ExtendedDerive_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Ike2PrfPlusDerive_MatchesBclViaSignProbe() => IkeDeriveTestCases.Assert_Ike2PrfPlusDerive_MatchesBclViaSignProbe(_backend);
}
