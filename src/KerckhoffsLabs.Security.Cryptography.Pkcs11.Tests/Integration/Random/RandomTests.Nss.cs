using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Random;

/// <summary>Cross-backend port of the SoftHSM2 RNG integration tests, run against NSS.</summary>
[Collection("Nss")]
public sealed class RandomTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;
    public static bool Available => NssBackendFixture.NssAvailable;

    [ConditionalFact(nameof(Available))]
    public void GenerateRandom_ProducesRequestedLength() => RandomTestCases.Assert_GenerateRandom_ProducesRequestedLength(_backend);

    [ConditionalFact(nameof(Available))]
    public void GenerateRandom_ConsecutiveCallsDiffer() => RandomTestCases.Assert_GenerateRandom_ConsecutiveCallsDiffer(_backend);

    [ConditionalFact(nameof(Available))]
    public void GenerateRandom_SpanOverload_FillsBuffer() => RandomTestCases.Assert_GenerateRandom_SpanOverload_FillsBuffer(_backend);
}
