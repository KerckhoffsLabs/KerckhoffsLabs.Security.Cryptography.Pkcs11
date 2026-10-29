using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>SP 800-108 feedback and double-pipeline KDFs over wolfPKCS11 — thin wrapper over <see cref="Sp800108ChainedKdfTestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class Sp800108ChainedKdfTests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void Feedback_HmacSha256_MatchesReference() =>
        Sp800108ChainedKdfTestCases.Assert_Feedback_HmacSha256_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void DoublePipeline_HmacSha256_MatchesReference() =>
        Sp800108ChainedKdfTestCases.Assert_DoublePipeline_HmacSha256_MatchesReference(_backend);
}
