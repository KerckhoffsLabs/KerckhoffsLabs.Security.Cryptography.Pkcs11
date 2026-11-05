using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>
/// SP 800-108 feedback and double-pipeline KDFs, and a counter-mode derive with an additional key, over FreeHSM
/// (2.6.0 and later) — thin wrapper over <see cref="Sp800108ChainedKdfTestCases"/>.
/// </summary>
[Collection("FreeHsm")]
public sealed class Sp800108ChainedKdfTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Feedback_HmacSha256_MatchesReference() =>
        Sp800108ChainedKdfTestCases.Assert_Feedback_HmacSha256_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void DoublePipeline_HmacSha256_MatchesReference() =>
        Sp800108ChainedKdfTestCases.Assert_DoublePipeline_HmacSha256_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Counter_AdditionalDerivedKey_TakesTheNextBytes() =>
        Sp800108ChainedKdfTestCases.Assert_Counter_AdditionalDerivedKey_TakesTheNextBytes(_backend);
}
