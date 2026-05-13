using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Internal.SafeHandles;

[Collection("Mock")]
public sealed class Pkcs11ModuleHandleTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void InvalidHandle_IsInvalid_Returns_True()
    {
        using var handle = new Pkcs11ModuleHandle();
        Assert.True(handle.IsInvalid);
    }

    [Fact]
    public void LoadedHandle_IsInvalid_Returns_False()
    {
        IntPtr raw = NativeLibrary.Load(_backend.LibraryPath);
        using var handle = new Pkcs11ModuleHandle(raw);
        Assert.False(handle.IsInvalid);
    }

    [Fact]
    public void Dispose_FreesUnderlyingHandle_AndMarksClosed()
    {
        IntPtr raw = NativeLibrary.Load(_backend.LibraryPath);
        var handle = new Pkcs11ModuleHandle(raw);
        Assert.False(handle.IsInvalid);
        handle.Dispose();
        Assert.True(handle.IsClosed);
    }
}
