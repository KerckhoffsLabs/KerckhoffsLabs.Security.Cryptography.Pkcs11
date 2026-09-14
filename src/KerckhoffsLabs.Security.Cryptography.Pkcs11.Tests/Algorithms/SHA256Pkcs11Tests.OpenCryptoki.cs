using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA256Pkcs11 over opencryptoki — thin wrapper over <see cref="SHA256Pkcs11TestCases"/>.
/// Each case skips if the backend does not advertise CKM_SHA256.</summary>
[Collection("OpenCryptoki")]
public sealed class SHA256Pkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [ConditionalFact(typeof(OpenCryptokiBackendFixture), nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ComputeHash_KnownAnswer_MatchesFips180Vector()
        => SHA256Pkcs11TestCases.Assert_ComputeHash_KnownAnswer_MatchesFips180Vector(_backend);

    [ConditionalFact(typeof(OpenCryptokiBackendFixture), nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ComputeHash_MatchesBclSha256()
        => SHA256Pkcs11TestCases.Assert_ComputeHash_MatchesBcl(_backend);

    [ConditionalFact(typeof(OpenCryptokiBackendFixture), nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void ComputeHash_Streamed_MatchesOneShot()
        => SHA256Pkcs11TestCases.Assert_ComputeHash_Streamed_MatchesOneShot(_backend);

    [ConditionalFact(typeof(OpenCryptokiBackendFixture), nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Reuse_AfterInitialize_ProducesFreshHash()
        => SHA256Pkcs11TestCases.Assert_Reuse_AfterInitialize_ProducesFreshHash(_backend);
}
