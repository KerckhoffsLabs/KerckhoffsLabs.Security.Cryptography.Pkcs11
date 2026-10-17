using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA512Pkcs11 over BouncyHsm — thin wrapper over <see cref="SHA512Pkcs11TestCases"/>.</summary>
[Collection("BouncyHsm")]
public sealed class SHA512Pkcs11Tests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ComputeHash_KnownAnswer() => SHA512Pkcs11TestCases.Assert_ComputeHash_KnownAnswer(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ComputeHash_MatchesBcl() => SHA512Pkcs11TestCases.Assert_ComputeHash_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot() => SHA512Pkcs11TestCases.Assert_ComputeHash_Streamed_MatchesOneShot(_backend);

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void Reuse_AfterInitialize_ProducesFreshHash() => SHA512Pkcs11TestCases.Assert_Reuse_AfterInitialize_ProducesFreshHash(_backend);
}
