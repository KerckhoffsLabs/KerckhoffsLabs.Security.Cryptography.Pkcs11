using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA3_384Pkcs11 over NSS softoken — thin wrapper over <see cref="SHA3_384Pkcs11TestCases"/>.</summary>
[Collection("Nss")]
public sealed class SHA3_384Pkcs11Tests_Nss(NssBackendFixture f)
{
    private readonly NssBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ComputeHash_KnownAnswer() => SHA3_384Pkcs11TestCases.Assert_ComputeHash_KnownAnswer(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ComputeHash_MatchesBcl() => SHA3_384Pkcs11TestCases.Assert_ComputeHash_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot() => SHA3_384Pkcs11TestCases.Assert_ComputeHash_Streamed_MatchesOneShot(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Reuse_AfterInitialize_ProducesFreshHash() => SHA3_384Pkcs11TestCases.Assert_Reuse_AfterInitialize_ProducesFreshHash(_backend);
}
