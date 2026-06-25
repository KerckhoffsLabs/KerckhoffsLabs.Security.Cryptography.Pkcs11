using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA3_256Pkcs11 over opencryptoki — thin wrapper over <see cref="SHA3_256Pkcs11TestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class SHA3_256Pkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_KnownAnswer() => SHA3_256Pkcs11TestCases.Assert_ComputeHash_KnownAnswer(_backend);

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_MatchesBcl() => SHA3_256Pkcs11TestCases.Assert_ComputeHash_MatchesBcl(_backend);

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_Streamed_MatchesOneShot() => SHA3_256Pkcs11TestCases.Assert_ComputeHash_Streamed_MatchesOneShot(_backend);

    [ConditionalFact(nameof(Available))]
    public void Reuse_AfterInitialize_ProducesFreshHash() => SHA3_256Pkcs11TestCases.Assert_Reuse_AfterInitialize_ProducesFreshHash(_backend);
}
