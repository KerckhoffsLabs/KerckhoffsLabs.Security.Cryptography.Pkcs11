using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA256Pkcs11 over Kryoptic — thin wrapper over <see cref="SHA256Pkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class SHA256Pkcs11Tests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ComputeHash_KnownAnswer_MatchesFips180Vector()
        => SHA256Pkcs11TestCases.Assert_ComputeHash_KnownAnswer_MatchesFips180Vector(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ComputeHash_MatchesBclSha256()
        => SHA256Pkcs11TestCases.Assert_ComputeHash_MatchesBcl(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot()
        => SHA256Pkcs11TestCases.Assert_ComputeHash_Streamed_MatchesOneShot(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Reuse_AfterInitialize_ProducesFreshHash()
        => SHA256Pkcs11TestCases.Assert_Reuse_AfterInitialize_ProducesFreshHash(_backend);
}
