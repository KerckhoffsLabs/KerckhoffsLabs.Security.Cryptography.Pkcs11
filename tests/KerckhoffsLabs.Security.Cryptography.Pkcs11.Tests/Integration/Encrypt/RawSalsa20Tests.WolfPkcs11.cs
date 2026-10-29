using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>Raw Salsa20 over wolfPKCS11, the only backend that offers it — thin wrapper over <see cref="RawSalsa20TestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class RawSalsa20Tests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Estream_Set1Vector0_Keystream() =>
        RawSalsa20TestCases.Assert_Estream_Set1Vector0_Keystream(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void TwoBlockMessage_MatchesReference_AndRoundTrips() =>
        RawSalsa20TestCases.Assert_TwoBlockMessage_MatchesReference_AndRoundTrips(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void NonZeroBlockCounter_StartsTheKeystreamThere() =>
        RawSalsa20TestCases.Assert_NonZeroBlockCounter_StartsTheKeystreamThere(_backend);
}
