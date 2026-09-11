using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA384Pkcs11 over Kryoptic — thin wrapper over <see cref="SHA384Pkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class SHA384Pkcs11Tests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ComputeHash_KnownAnswer() => SHA384Pkcs11TestCases.Assert_ComputeHash_KnownAnswer(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ComputeHash_MatchesBcl() => SHA384Pkcs11TestCases.Assert_ComputeHash_MatchesBcl(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot() => SHA384Pkcs11TestCases.Assert_ComputeHash_Streamed_MatchesOneShot(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Reuse_AfterInitialize_ProducesFreshHash() => SHA384Pkcs11TestCases.Assert_Reuse_AfterInitialize_ProducesFreshHash(_backend);
}
