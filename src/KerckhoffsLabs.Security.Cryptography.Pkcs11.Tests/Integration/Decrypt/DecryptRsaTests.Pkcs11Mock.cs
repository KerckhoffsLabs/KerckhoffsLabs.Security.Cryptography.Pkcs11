using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>RSA PKCS#1 v1.5 gate against pkcs11-mock (the managed gate fires before C_DecryptInit).</summary>
[Collection("Mock")]
public sealed class DecryptRsaTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void RsaPkcs1V15_ThrowsInsecureOperationException_ByDefault_Mock()
        => DecryptRsaTestCases.Assert_RsaPkcs1V15_GatedByDefault(_backend);
}
