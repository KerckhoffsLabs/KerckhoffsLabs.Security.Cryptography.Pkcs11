using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Discovery;

/// <summary>
/// <c>Pkcs11Library.GetInterface</c> over pkcs11-mock's native <c>C_GetInterface</c> — the real
/// P/Invoke path (token-owned CK_INTERFACE read-back, including the Pack=1 sibling layout on
/// Windows). Complements the hermetic <c>GetInterfaceTests</c>, which fakes the descriptor.
/// </summary>
[Collection("Mock")]
public sealed class GetInterfaceTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void GetInterface_Default_ReturnsPkcs11Interface()
    {
        var info = _backend.Library.GetInterface();
        Assert.Equal("PKCS 11", info.Name);
    }

    [Fact]
    public void GetInterface_ByName_ReturnsPkcs11Interface()
    {
        var info = _backend.Library.GetInterface("PKCS 11");
        Assert.Equal("PKCS 11", info.Name);
    }
}
