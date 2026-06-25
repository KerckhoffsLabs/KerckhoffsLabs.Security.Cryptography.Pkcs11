using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA3_512Pkcs11 over SoftHSM — thin wrapper over <see cref="SHA3_512Pkcs11TestCases"/>.</summary>
[Collection("SoftHsm")]
public sealed class SHA3_512Pkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_KnownAnswer() => SHA3_512Pkcs11TestCases.Assert_ComputeHash_KnownAnswer(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_MatchesBcl() => SHA3_512Pkcs11TestCases.Assert_ComputeHash_MatchesBcl(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot() => SHA3_512Pkcs11TestCases.Assert_ComputeHash_Streamed_MatchesOneShot(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Reuse_AfterInitialize_ProducesFreshHash() => SHA3_512Pkcs11TestCases.Assert_Reuse_AfterInitialize_ProducesFreshHash(_backend);
}
