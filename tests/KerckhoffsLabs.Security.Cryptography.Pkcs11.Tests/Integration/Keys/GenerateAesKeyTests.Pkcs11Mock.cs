using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

[Collection("Mock")]
public sealed class GenerateAesKeyTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void RejectsWrongBitLength() => GenerateAesKeyTestCases.Assert_RejectsWrongBitLength(_backend);
}
