using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Discovery;

/// <summary>
/// <c>Pkcs11Library.GetInterfaces</c> over pkcs11-mock's <c>C_GetInterfaceList</c>, which reports
/// two "PKCS 11" interfaces (v2.40 and v3.1). Exercises the two-call idiom and, on Windows, the
/// CK_INTERFACE Pack=1 sibling readback.
/// </summary>
[Collection("Mock")]
public sealed class GetInterfacesTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void GetInterfaces_EnumeratesModuleInterfaces()
    {
        var interfaces = _backend.Library.GetInterfaces();

        Assert.Equal(2, interfaces.Count);
        Assert.All(interfaces, i => Assert.Equal("PKCS 11", i.Name));
        // The mock advertises flags = 0 on both interfaces.
        Assert.All(interfaces, i => Assert.False(i.InterfaceFlags.ForkSafe));
        Assert.All(interfaces, i => Assert.Equal(0UL, i.InterfaceFlags.Flags));
    }
}
