using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Random;

[Collection("SoftHsm")]
public sealed class RandomTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateRandom_ProducesRequestedLength() => RandomTestCases.Assert_GenerateRandom_ProducesRequestedLength(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateRandom_ConsecutiveCallsDiffer() => RandomTestCases.Assert_GenerateRandom_ConsecutiveCallsDiffer(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateRandom_SpanOverload_FillsBuffer() => RandomTestCases.Assert_GenerateRandom_SpanOverload_FillsBuffer(_backend);
}
