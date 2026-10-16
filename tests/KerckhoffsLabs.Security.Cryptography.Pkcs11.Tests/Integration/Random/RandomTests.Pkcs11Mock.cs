using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Random;

[Collection("Mock")]
public sealed class RandomTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void GenerateRandom_ProducesRequestedLength() => RandomTestCases.Assert_GenerateRandom_ProducesRequestedLength(_backend);

    // ConsecutiveCallsDiffer / SpanOverload_FillsBuffer are SoftHsm-only — pkcs11-mock returns
    // the same canned bytes, so a difference/non-zero assertion would be meaningless here.
}
