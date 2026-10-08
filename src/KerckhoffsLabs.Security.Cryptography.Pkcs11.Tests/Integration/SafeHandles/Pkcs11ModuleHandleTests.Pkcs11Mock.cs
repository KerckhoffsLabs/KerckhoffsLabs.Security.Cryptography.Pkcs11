using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.SafeHandles;

[Collection("Mock")]
public sealed class Pkcs11ModuleHandleTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void Load_BindsTheTable_AndDisposeClosesTheHandle()
    {
        var handle = Pkcs11ModuleHandle.Load(_backend.LibraryPath);
        Assert.False(handle.IsInvalid);
        Assert.NotNull(handle.Table);

        handle.Dispose();

        Assert.True(handle.IsClosed);
    }
}
