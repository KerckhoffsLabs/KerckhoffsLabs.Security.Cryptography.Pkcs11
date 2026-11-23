using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>Raw-output entry points over FreeHSM — thin wrapper over <see cref="RawOutputTestCases"/>.</summary>
[Collection("FreeHsm")]
public sealed class RawOutputTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void X25519_DeriveRawSecret_MatchesBcl() => RawOutputTestCases.Assert_X25519_DeriveRawSecret_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void X448_DeriveRawSecret_MatchesBcl() => RawOutputTestCases.Assert_X448_DeriveRawSecret_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void X25519_WrongCurvePeer_Throws() => RawOutputTestCases.Assert_X25519_WrongCurvePeer_Throws(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void X25519_ZeroPeer_Throws() => RawOutputTestCases.Assert_X25519_ZeroPeer_Throws(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void X25519_DeriveSecretAgreement_ThenHkdf_MatchesRfc7748() => RawOutputTestCases.Assert_X25519_DeriveSecretAgreement_ThenHkdf_MatchesRfc7748(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void X448_DeriveSecretAgreement_ThenHkdf_MatchesRfc7748() => RawOutputTestCases.Assert_X448_DeriveSecretAgreement_ThenHkdf_MatchesRfc7748(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void X25519_DeriveSecretAgreement_LowOrderPeer_Throws() => RawOutputTestCases.Assert_X25519_DeriveSecretAgreement_LowOrderPeer_Throws(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void DeriveBytes_Sp800108Feedback_MatchesReference() => RawOutputTestCases.Assert_DeriveBytes_Sp800108Feedback_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void DeriveBytes_OverAnAgreedSecret_NeverProtectedScope() => RawOutputTestCases.Assert_DeriveBytes_OverAnAgreedSecret_NeverProtectedScope(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void DeriveRawSecret_SessionObjectsScope() => RawOutputTestCases.Assert_DeriveRawSecret_SessionObjectsScope(_backend);
}
