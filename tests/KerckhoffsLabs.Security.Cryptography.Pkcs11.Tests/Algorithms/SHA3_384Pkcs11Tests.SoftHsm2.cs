using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA3_384Pkcs11 over SoftHSM — thin wrapper over <see cref="SHA3_384Pkcs11TestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class SHA3_384Pkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ComputeHash_KnownAnswer() => SHA3_384Pkcs11TestCases.Assert_ComputeHash_KnownAnswer(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ComputeHash_MatchesBcl() => SHA3_384Pkcs11TestCases.Assert_ComputeHash_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot() => SHA3_384Pkcs11TestCases.Assert_ComputeHash_Streamed_MatchesOneShot(_backend);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void Reuse_AfterInitialize_ProducesFreshHash() => SHA3_384Pkcs11TestCases.Assert_Reuse_AfterInitialize_ProducesFreshHash(_backend);
}
