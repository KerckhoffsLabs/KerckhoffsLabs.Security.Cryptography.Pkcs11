using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>Raw-output entry points over Kryoptic — thin wrapper over <see cref="RawOutputTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class RawOutputTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void X25519_DeriveRawSecret_MatchesBcl() => RawOutputTestCases.Assert_X25519_DeriveRawSecret_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void X448_DeriveRawSecret_MatchesBcl() => RawOutputTestCases.Assert_X448_DeriveRawSecret_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void X25519_WrongCurvePeer_Throws() => RawOutputTestCases.Assert_X25519_WrongCurvePeer_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void X25519_ZeroPeer_Throws() => RawOutputTestCases.Assert_X25519_ZeroPeer_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void DeriveBytes_Sp800108Feedback_MatchesReference() => RawOutputTestCases.Assert_DeriveBytes_Sp800108Feedback_MatchesReference(_backend);
}
