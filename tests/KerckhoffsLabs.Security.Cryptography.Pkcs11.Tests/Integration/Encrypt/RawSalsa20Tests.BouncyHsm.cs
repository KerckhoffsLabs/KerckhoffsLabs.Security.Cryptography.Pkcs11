using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>Raw Salsa20 over BouncyHsm, the only backend that offers it — thin wrapper over <see cref="RawSalsa20TestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class RawSalsa20Tests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Estream_Set1Vector0_Keystream() =>
        RawSalsa20TestCases.Assert_Estream_Set1Vector0_Keystream(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void TwoBlockMessage_MatchesReference_AndRoundTrips() =>
        RawSalsa20TestCases.Assert_TwoBlockMessage_MatchesReference_AndRoundTrips(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void NonZeroBlockCounter_StartsTheKeystreamThere() =>
        RawSalsa20TestCases.Assert_NonZeroBlockCounter_StartsTheKeystreamThere(_backend);
}
