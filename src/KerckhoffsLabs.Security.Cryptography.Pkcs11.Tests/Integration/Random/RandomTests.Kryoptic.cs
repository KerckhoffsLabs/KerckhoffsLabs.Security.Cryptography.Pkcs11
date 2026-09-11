using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Random;

[Collection("Kryoptic")]
public sealed class RandomTests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(KryopticAvailable))]
    public void GenerateRandom_ProducesRequestedLength() => RandomTestCases.Assert_GenerateRandom_ProducesRequestedLength(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void GenerateRandom_ConsecutiveCallsDiffer() => RandomTestCases.Assert_GenerateRandom_ConsecutiveCallsDiffer(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void GenerateRandom_SpanOverload_FillsBuffer() => RandomTestCases.Assert_GenerateRandom_SpanOverload_FillsBuffer(_backend);
}
