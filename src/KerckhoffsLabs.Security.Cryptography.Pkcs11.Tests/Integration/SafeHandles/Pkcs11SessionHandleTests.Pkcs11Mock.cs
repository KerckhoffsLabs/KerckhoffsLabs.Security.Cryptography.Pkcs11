using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.SafeHandles;

[Collection("Mock")]
public sealed class Pkcs11SessionHandleTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void InvalidHandle_IsInvalid_Returns_True()
    {
        var lib = GetLowLevelLibrary();
        using var handle = new Pkcs11SessionHandle(lib, CK.CK_INVALID_HANDLE);
        Assert.True(handle.IsInvalid);
    }

    [Fact]
    public void ValidHandle_SessionId_RoundTrips()
    {
        var sid = (NativeCULong)42;
        var lib = GetLowLevelLibrary();
        using var handle = new Pkcs11SessionHandle(lib, sid);
        Assert.Equal(sid, handle.SessionId);
        Assert.False(handle.IsInvalid);
    }

    [Fact]
    public void Constructor_RejectsNullLibrary() => Assert.Throws<ArgumentNullException>(() => new Pkcs11SessionHandle(null!, (NativeCULong)1));

    private LowLevelPkcs11Library GetLowLevelLibrary() => new LowLevelPkcs11Library(_backend.LibraryPath);
}
