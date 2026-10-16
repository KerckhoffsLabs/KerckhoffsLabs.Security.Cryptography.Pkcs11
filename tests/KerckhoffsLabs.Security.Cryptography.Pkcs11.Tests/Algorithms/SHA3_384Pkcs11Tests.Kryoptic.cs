using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA3_384Pkcs11 over Kryoptic — thin wrapper over <see cref="SHA3_384Pkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class SHA3_384Pkcs11Tests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ComputeHash_KnownAnswer() => SHA3_384Pkcs11TestCases.Assert_ComputeHash_KnownAnswer(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ComputeHash_MatchesBcl() => SHA3_384Pkcs11TestCases.Assert_ComputeHash_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot() => SHA3_384Pkcs11TestCases.Assert_ComputeHash_Streamed_MatchesOneShot(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Reuse_AfterInitialize_ProducesFreshHash() => SHA3_384Pkcs11TestCases.Assert_Reuse_AfterInitialize_ProducesFreshHash(_backend);
}
