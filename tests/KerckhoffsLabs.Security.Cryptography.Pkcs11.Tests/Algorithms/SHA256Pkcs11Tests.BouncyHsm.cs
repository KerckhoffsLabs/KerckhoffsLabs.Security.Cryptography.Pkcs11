using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA256Pkcs11 over BouncyHsm — thin wrapper over <see cref="SHA256Pkcs11TestCases"/>.
/// Each case skips if the backend does not advertise CKM_SHA256.</summary>
[Collection("BouncyHsm")]
public sealed class SHA256Pkcs11Tests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ComputeHash_KnownAnswer_MatchesFips180Vector()
        => SHA256Pkcs11TestCases.Assert_ComputeHash_KnownAnswer_MatchesFips180Vector(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ComputeHash_MatchesBclSha256()
        => SHA256Pkcs11TestCases.Assert_ComputeHash_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot()
        => SHA256Pkcs11TestCases.Assert_ComputeHash_Streamed_MatchesOneShot(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Reuse_AfterInitialize_ProducesFreshHash()
        => SHA256Pkcs11TestCases.Assert_Reuse_AfterInitialize_ProducesFreshHash(_backend);
}
