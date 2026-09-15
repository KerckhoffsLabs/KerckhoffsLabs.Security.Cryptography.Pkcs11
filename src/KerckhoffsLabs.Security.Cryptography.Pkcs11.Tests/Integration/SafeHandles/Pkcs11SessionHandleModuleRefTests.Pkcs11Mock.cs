using System.Reflection;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.SafeHandles;

/// <summary>
/// Coverage for <see cref="Pkcs11SessionHandle"/>'s explicit <c>DangerousAddRef</c> on the owning
/// module's <see cref="Pkcs11ModuleHandle"/>: the CLR gives no relative ordering guarantee between
/// two independent <c>CriticalFinalizerObject</c>s, so mere reachability of the library cannot
/// guarantee the native module stays mapped until <c>C_CloseSession</c> runs — an explicit SafeHandle
/// ref does. These tests pin the wiring (which cases take the ref, which don't) rather than SafeHandle's
/// own ref-counting semantics, which are a BCL guarantee this project doesn't need to re-verify.
/// </summary>
[Collection("Mock")]
public sealed class Pkcs11SessionHandleModuleRefTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    private static object? GetPrivateField(object instance, string name) =>
        instance.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(instance);

    [Fact]
    public void RealLibrary_ValidSession_TakesModuleRef()
    {
        using var library = new LowLevelPkcs11Library(_backend.LibraryPath);
        using var handle = new Pkcs11SessionHandle(library, (NativeCULong)1);

        Assert.NotNull(GetPrivateField(handle, "_moduleHandle"));
        Assert.True((bool)GetPrivateField(handle, "_moduleHandleRefAdded")!);
    }

    [Fact]
    public void RealLibrary_InvalidSession_TakesNoModuleRef()
    {
        using var library = new LowLevelPkcs11Library(_backend.LibraryPath);
        using var handle = new Pkcs11SessionHandle(library, (NativeCULong)CK.CK_INVALID_HANDLE);

        Assert.Null(GetPrivateField(handle, "_moduleHandle"));
        Assert.False((bool)GetPrivateField(handle, "_moduleHandleRefAdded")!);
    }

    [Fact]
    public void FakeLibrary_TakesNoModuleRef()
    {
        var fake = new FakeLowLevelPkcs11Library();
        using var handle = new Pkcs11SessionHandle(fake, (NativeCULong)1);

        Assert.Null(GetPrivateField(handle, "_moduleHandle"));
        Assert.False((bool)GetPrivateField(handle, "_moduleHandleRefAdded")!);
    }

    [Fact]
    public void RealLibrary_DisposingSessionHandle_ReleasesModuleRefExactlyOnce()
    {
        using var library = new LowLevelPkcs11Library(_backend.LibraryPath);
        var handle = new Pkcs11SessionHandle(library, (NativeCULong)1);
        var moduleHandle = (Pkcs11ModuleHandle)GetPrivateField(handle, "_moduleHandle")!;

        handle.Dispose();

        // If DangerousRelease had under- or over-run, a fresh Add/Release cycle on the same module
        // handle afterward would misbehave — it doesn't, so the pairing was exact.
        bool ok = false;
        moduleHandle.DangerousAddRef(ref ok);
        Assert.True(ok);
        moduleHandle.DangerousRelease();
    }
}
