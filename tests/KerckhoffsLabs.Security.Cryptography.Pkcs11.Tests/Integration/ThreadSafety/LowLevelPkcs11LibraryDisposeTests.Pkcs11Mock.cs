using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.ThreadSafety;

/// <summary>
/// A call that begins after <c>LowLevelPkcs11Library.Dispose</c> is turned away against a real module.
/// What happens to a call already in flight is <see cref="LibraryDisposeRaceTests"/>'s concern.
/// </summary>
[Collection("Mock")]
public sealed class LowLevelPkcs11LibraryDisposeTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void Dispose_ThenNativeCall_ThrowsObjectDisposedException()
    {
        var lib = new LowLevelPkcs11Library(_backend.LibraryPath);
        lib.Dispose();

        var info = new CK_INFO();
        Assert.Throws<ObjectDisposedException>(() => lib.C_GetInfo(ref info));
    }
}
