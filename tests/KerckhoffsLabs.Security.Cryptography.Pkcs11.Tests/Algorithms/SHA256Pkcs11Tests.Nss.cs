using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA256Pkcs11 over NSS softoken — thin wrapper over <see cref="SHA256Pkcs11TestCases"/>.</summary>
[Collection("Nss")]
public sealed class SHA256Pkcs11Tests_Nss(NssBackendFixture f)
{
    private readonly NssBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ComputeHash_KnownAnswer_MatchesFips180Vector()
        => SHA256Pkcs11TestCases.Assert_ComputeHash_KnownAnswer_MatchesFips180Vector(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ComputeHash_MatchesBclSha256()
        => SHA256Pkcs11TestCases.Assert_ComputeHash_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot()
        => SHA256Pkcs11TestCases.Assert_ComputeHash_Streamed_MatchesOneShot(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Reuse_AfterInitialize_ProducesFreshHash()
        => SHA256Pkcs11TestCases.Assert_Reuse_AfterInitialize_ProducesFreshHash(_backend);
}
