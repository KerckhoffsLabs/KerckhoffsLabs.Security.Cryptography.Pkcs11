using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>SP 800-108 feedback and double-pipeline KDFs over BouncyHsm — thin wrapper over <see cref="Sp800108ChainedKdfTestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class Sp800108ChainedKdfTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Feedback_HmacSha256_MatchesReference() =>
        Sp800108ChainedKdfTestCases.Assert_Feedback_HmacSha256_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void DoublePipeline_HmacSha256_MatchesReference() =>
        Sp800108ChainedKdfTestCases.Assert_DoublePipeline_HmacSha256_MatchesReference(_backend);
}
