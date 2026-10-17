using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>SP 800-108 feedback and double-pipeline KDFs over Kryoptic — thin wrapper over <see cref="Sp800108ChainedKdfTestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class Sp800108ChainedKdfTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Feedback_HmacSha256_MatchesReference() =>
        Sp800108ChainedKdfTestCases.Assert_Feedback_HmacSha256_MatchesReference(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void DoublePipeline_HmacSha256_MatchesReference() =>
        Sp800108ChainedKdfTestCases.Assert_DoublePipeline_HmacSha256_MatchesReference(_backend);
}
