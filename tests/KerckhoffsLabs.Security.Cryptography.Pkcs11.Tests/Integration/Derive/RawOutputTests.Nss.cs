using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>Raw-output entry points over NSS softoken — thin wrapper over <see cref="RawOutputTestCases"/>.</summary>
[Collection("Nss")]
public sealed class RawOutputTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void X25519_DeriveRawSecret_MatchesBcl() => RawOutputTestCases.Assert_X25519_DeriveRawSecret_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void X448_DeriveRawSecret_MatchesBcl() => RawOutputTestCases.Assert_X448_DeriveRawSecret_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void X25519_WrongCurvePeer_Throws() => RawOutputTestCases.Assert_X25519_WrongCurvePeer_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void X25519_ZeroPeer_Throws() => RawOutputTestCases.Assert_X25519_ZeroPeer_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void DeriveBytes_Sp800108Feedback_MatchesReference() => RawOutputTestCases.Assert_DeriveBytes_Sp800108Feedback_MatchesReference(_backend);
}
