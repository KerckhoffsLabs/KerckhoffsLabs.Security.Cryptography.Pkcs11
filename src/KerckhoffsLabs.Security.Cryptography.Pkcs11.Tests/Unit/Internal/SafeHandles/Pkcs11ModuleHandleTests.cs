using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal.SafeHandles;

/// <summary>
/// Hermetic coverage for <see cref="Pkcs11ModuleHandle"/>. The invalid-handle states need no
/// native module; the release path is exercised against a real, already-present OS library
/// (loaded independently so the handle owns its own reference) rather than a PKCS#11 module —
/// the only release coverage the Integration suite otherwise provides.
/// </summary>
public sealed class Pkcs11ModuleHandleTests
{
    // Pick whichever ubiquitous OS library happens to be present on the running platform; the
    // test skips if none load (keeps the suite green on an unexpected runtime).
    private static readonly string[] Candidates =
        ["libc.so.6", "libSystem.B.dylib", "kernel32.dll", "libc.dylib", "libdl.so.2", "msvcrt.dll"];

    private static readonly string? LoadableLib = FindLoadableLib();
    public static bool NativeLibAvailable => LoadableLib is not null;

    private static string? FindLoadableLib() => Candidates.FirstOrDefault(CanLoad);

    /// <summary>
    /// Whether this library can be loaded, leaving the process as it found it.
    /// </summary>
    /// <remarks>
    /// The release is why this is a named method and not a lambda in the query above: probing with
    /// <c>TryLoad(name, out _)</c> would load each candidate and drop its handle on the floor, so the
    /// tidier-looking version would leak a native module reference per probe.
    /// </remarks>
    private static bool CanLoad(string name)
    {
        if (!NativeLibrary.TryLoad(name, out IntPtr handle))
            return false;

        NativeLibrary.Free(handle); // release the probe; the test re-loads to get its own ref
        return true;
    }

    [Fact]
    public void DefaultCtor_IsInvalid()
    {
        using var handle = new Pkcs11ModuleHandle();
        Assert.True(handle.IsInvalid);
    }

    [Fact]
    public void Ctor_WithZeroHandle_IsInvalid()
    {
        using var handle = new Pkcs11ModuleHandle(IntPtr.Zero);
        Assert.True(handle.IsInvalid);
    }

    [Fact]
    public void Dispose_InvalidHandle_DoesNotThrow()
    {
        var handle = new Pkcs11ModuleHandle();
        Assert.Null(Record.Exception(handle.Dispose));
        Assert.True(handle.IsClosed);
    }

    [ConditionalFact(nameof(NativeLibAvailable))]
    public void Ctor_WithRealHandle_IsValid_AndDisposeFreesIt()
    {
        Assert.True(NativeLibrary.TryLoad(LoadableLib!, out IntPtr nativeHandle));

        var handle = new Pkcs11ModuleHandle(nativeHandle);
        Assert.False(handle.IsInvalid);

        handle.Dispose(); // ReleaseHandle -> NativeLibrary.Free, returns true

        Assert.True(handle.IsClosed);
    }
}
