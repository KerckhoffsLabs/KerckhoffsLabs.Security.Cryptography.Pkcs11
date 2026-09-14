using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA384Pkcs11 over opencryptoki — thin wrapper over <see cref="SHA384Pkcs11TestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class SHA384Pkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [ConditionalFact(typeof(OpenCryptokiBackendFixture), nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ComputeHash_KnownAnswer() => SHA384Pkcs11TestCases.Assert_ComputeHash_KnownAnswer(_backend);

    [ConditionalFact(typeof(OpenCryptokiBackendFixture), nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ComputeHash_MatchesBcl() => SHA384Pkcs11TestCases.Assert_ComputeHash_MatchesBcl(_backend);

    [ConditionalFact(typeof(OpenCryptokiBackendFixture), nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot() => SHA384Pkcs11TestCases.Assert_ComputeHash_Streamed_MatchesOneShot(_backend);

    [ConditionalFact(typeof(OpenCryptokiBackendFixture), nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Reuse_AfterInitialize_ProducesFreshHash() => SHA384Pkcs11TestCases.Assert_Reuse_AfterInitialize_ProducesFreshHash(_backend);
}
