using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.SafeHandles;

/// <summary>
/// Every valid <see cref="Pkcs11SessionHandle"/> takes a reference on its <see cref="Pkcs11ModuleHandle"/>
/// and is tracked by it: the CLR gives no relative ordering between two critical finalizers, so only that reference keeps the
/// module usable until the session's <c>C_CloseSession</c> has run.
/// </summary>
[Collection("Mock")]
public sealed class Pkcs11SessionHandleModuleRefTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void RealLibrary_ValidSession_IsTracked_UntilDisposed()
    {
        using var library = new LowLevelPkcs11Library(_backend.LibraryPath);
        var handle = new Pkcs11SessionHandle(library, (NativeCULong)1);
        Assert.Equal(1, library.Module.TrackedSessionCount);

        handle.Dispose();

        Assert.Equal(0, library.Module.TrackedSessionCount);
    }

    [Fact]
    public void InvalidSession_IsNotTracked()
    {
        using var library = new LowLevelPkcs11Library(_backend.LibraryPath);
        using var handle = new Pkcs11SessionHandle(library, (NativeCULong)CK.CK_INVALID_HANDLE);

        Assert.Equal(0, library.Module.TrackedSessionCount);
    }

    [Fact]
    public void RealLibrary_DisposingSessionHandle_ReleasesModuleRefExactlyOnce()
    {
        using var library = new LowLevelPkcs11Library(_backend.LibraryPath);
        var handle = new Pkcs11SessionHandle(library, (NativeCULong)1);

        handle.Dispose();

        // If DangerousRelease had under- or over-run, a fresh Add/Release cycle on the same module
        // handle afterward would misbehave — it doesn't, so the pairing was exact.
        bool ok = false;
        library.Module.DangerousAddRef(ref ok);
        Assert.True(ok);
        library.Module.DangerousRelease();
    }
}

/// <summary>
/// The same reference and tracking for a session on a <see cref="FakeModule"/>, in the fake-module
/// collection: at most one such module may be active at a time.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionHandleFakeModuleRefTests
{
    // A fake module's session gets the same reference and tracking as a real module's.
    [Fact]
    public void FakeLibrary_ValidSession_IsTracked_AndClosesAfterTheLibraryIsDisposed()
    {
        using var module = new ClosingFake();
        var fake = module.LoadLowLevel();
        var handle = new Pkcs11SessionHandle(fake, (NativeCULong)1);
        Assert.Equal(1, fake.Module.TrackedSessionCount);

        fake.Dispose();
        handle.Dispose();

        Assert.Equal(1, module.CloseCalls);
    }

    private sealed class ClosingFake : FakeModule
    {
        public int CloseCalls { get; private set; }

        protected override CKR C_CloseSession(NativeCULong session)
        {
            CloseCalls++;
            return CKR.CKR_OK;
        }
    }
}
