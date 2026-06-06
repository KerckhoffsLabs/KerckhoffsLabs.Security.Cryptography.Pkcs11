using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Digest;

// Gate fires in managed C# before C_DigestInit — no real crypto required.
[Collection("Mock")]
public sealed class DigestMd5Sha1Tests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void Md5_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Md5_GatedByDefault(_backend);

    [Fact]
    public void Sha1_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Sha1_GatedByDefault(_backend);

    [Fact]
    public void Md5_AllowInsecureBypassesGate() => DigestMd5Sha1TestCases.Assert_Md5_AllowInsecureBypassesGate(_backend);
}
