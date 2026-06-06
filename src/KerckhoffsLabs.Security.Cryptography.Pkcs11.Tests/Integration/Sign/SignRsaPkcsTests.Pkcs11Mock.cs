using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

// Gate fires in managed C# before C_SignInit — no real crypto required.
[Collection("Mock")]
public sealed class SignRsaPkcsTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void SignRsaPkcs1V15_GatedByDefault()
        => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_GatedByDefault(_backend);

    [Fact]
    public void SignRsaPkcs1V15_AllowInsecureBypassesGate()
        => SignRsaPkcsTestCases.Assert_SignRsaPkcs1V15_AllowInsecureBypassesGate(_backend);
}
