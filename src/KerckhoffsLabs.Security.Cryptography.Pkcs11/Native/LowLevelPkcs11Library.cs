using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library : ILowLevelPkcs11Library
{

    private volatile bool _disposed = false;

    /// <summary>
    /// Handle to the PKCS#11 library
    /// </summary>
    private readonly Pkcs11ModuleHandle _library = new();

    /// <summary>
    /// Delegates for PKCS#11 functions
    /// </summary>
    private readonly Delegates _delegates;

    /// <summary>
    /// Lock guarding <see cref="_trackedSessions"/>.
    /// </summary>
    private readonly Lock _sessionsLock = new();

    /// <summary>
    /// Weak references to every <see cref="Pkcs11SessionHandle"/> opened against this library.
    /// Cleared by <see cref="CloseAllTrackedSessions"/> at <see cref="Pkcs11Library.Dispose()"/>
    /// time so we can issue a graceful <c>C_CloseSession</c> while the function table is still
    /// valid — without preventing GC of normally-disposed sessions.
    /// </summary>
    private readonly List<WeakReference<Pkcs11SessionHandle>> _trackedSessions = [];

    /// <summary>
    /// Test seam: current count of tracked (still-live) session handles. Prunes dead
    /// weak refs on read so the count reflects what's actually reachable.
    /// </summary>
    public int TrackedSessionCount
    {
        get
        {
            lock (_sessionsLock)
            {
                _trackedSessions.RemoveAll(wr => !wr.TryGetTarget(out _));
                return _trackedSessions.Count;
            }
        }
    }

    /// <summary>
    /// Registers a session handle for cleanup at library teardown. Called from the
    /// <see cref="Pkcs11SessionHandle"/> constructor.
    /// </summary>
    public void RegisterSession(Pkcs11SessionHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        lock (_sessionsLock)
        {
            _trackedSessions.RemoveAll(wr => !wr.TryGetTarget(out _));
            _trackedSessions.Add(new WeakReference<Pkcs11SessionHandle>(handle));
        }
    }

    /// <summary>
    /// Removes <paramref name="handle"/> from the tracker. Called from
    /// <see cref="Pkcs11SessionHandle.ReleaseHandle"/> after a normal close so the
    /// tracker doesn't grow unbounded.
    /// </summary>
    public void UnregisterSession(Pkcs11SessionHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        lock (_sessionsLock)
        {
            _trackedSessions.RemoveAll(wr =>
                !wr.TryGetTarget(out var h) || ReferenceEquals(h, handle));
        }
    }

    /// <summary>
    /// Closes every still-live tracked session handle. Must run before <c>C_Finalize</c>
    /// and before the module is unloaded — otherwise a stray <see cref="Pkcs11SessionHandle"/>
    /// finalizer would call <c>C_CloseSession</c> through a function table whose backing
    /// module has been unmapped. <see cref="SafeHandle.Dispose()"/> is reentrant and
    /// thread-safe, so it's safe to invoke even if the user races us by disposing the same
    /// session on another thread.
    /// </summary>
    public void CloseAllTrackedSessions()
    {
        Pkcs11SessionHandle[] live;
        lock (_sessionsLock)
        {
            live = [.. _trackedSessions
                .Select(wr => wr.TryGetTarget(out var h) ? h : null)
                .Where(h => h is not null)
                .Cast<Pkcs11SessionHandle>()];
            _trackedSessions.Clear();
        }

        foreach (var handle in live)
        {
            try
            {
                if (handle.IsClosed || handle.IsInvalid) continue;
                handle.Dispose();
            }
            catch
            {
                // Best-effort cleanup; never let one bad handle block another's close.
            }
        }
    }

    /// <summary>
    /// Loads PKCS#11 library at <paramref name="libraryPath"/> and acquires function
    /// pointers via <c>C_GetFunctionList</c>.
    /// </summary>
    /// <param name="libraryPath">Library name or path.</param>
    public LowLevelPkcs11Library(string libraryPath)
    {
        EnsureCkUlongWidthMatchesPlatform();
        ArgumentException.ThrowIfNullOrEmpty(libraryPath);
        try
        {
            _library = new Pkcs11ModuleHandle(NativeLibrary.Load(libraryPath));

            // Delegates resolves the function-pointer table via NativeLibrary.GetExport, which
            // needs the raw module handle. DangerousGetHandle is the only way to obtain it from the
            // SafeHandle; bracket it with DangerousAddRef/DangerousRelease so the module cannot be
            // unloaded while symbols are resolved. The raw pointer is consumed entirely within the
            // Delegates constructor and never retained, so it cannot outlive the ref.
            bool addedRef = false;
            try
            {
                _library.DangerousAddRef(ref addedRef);
#pragma warning disable S3869 // DangerousGetHandle is unavoidable for NativeLibrary.GetExport and is bracketed by DangerousAddRef/Release.
                _delegates = new Delegates(_library.DangerousGetHandle());
#pragma warning restore S3869
            }
            finally
            {
                if (addedRef)
                    _library.DangerousRelease();
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>
    /// Binds to a statically-linked PKCS#11 implementation. The cryptoki symbols are expected to be
    /// linked into the host executable and exported from it, so <c>C_GetFunctionList</c> resolves
    /// against the entry-point module's own symbol table. All subsequent calls go through the
    /// returned function-pointer table, same as the dynamic-load path.
    /// </summary>
    internal LowLevelPkcs11Library()
    {
        EnsureCkUlongWidthMatchesPlatform();
        try
        {
            _delegates = new Delegates(IntPtr.Zero);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>
    /// Verifies the resolved build's CK_ULONG width (<see cref="NativeCULong"/>) matches the
    /// host's native CK_ULONG: 4 bytes on Windows (LLP64), the pointer width on Unix (LP64/ILP32).
    /// <see cref="NativeCULong"/> is <c>uint</c> in the net10.0-windows build and <c>nuint</c> in
    /// the neutral net10.0 build, so a net10.0 build on Windows x64 (8 bytes) or a net10.0-windows
    /// build on Unix-64 (4 bytes) would silently mis-marshal every CK_ULONG-bearing struct. Fail
    /// loudly instead — the caller resolved the wrong target-framework asset.
    /// </summary>
    private static void EnsureCkUlongWidthMatchesPlatform()
    {
        int expected = OperatingSystem.IsWindows() ? sizeof(uint) : IntPtr.Size;
        // Unsafe.SizeOf, not Marshal.SizeOf: what can mis-marshal is the by-value CK_ULONG in the
        // delegate* unmanaged[Cdecl] signatures, and [assembly: DisableRuntimeMarshalling] makes those
        // use the blittable layout. NativeCULong wraps a single primitive so the two sizes agree, but
        // this guard should measure the layout that actually crosses the boundary.
        int actual = Unsafe.SizeOf<NativeCULong>();
        if (actual != expected)
        {
            throw new PlatformNotSupportedException(
                $"CK_ULONG width mismatch: this build's NativeCULong is {actual} bytes but the " +
                $"native CK_ULONG on this platform is {expected} bytes. On Windows, reference " +
                "KerckhoffsLabs.Security.Cryptography.Pkcs11 from a net10.0-windows target framework " +
                "so the 4-byte build is resolved; on Unix use the neutral net10.0 build.");
        }
    }

    /// <summary>
    /// True when the loaded PKCS#11 library exposes the v3.0 message-based AEAD
    /// functions (C_MessageEncryptInit / C_EncryptMessage / C_MessageEncryptFinal +
    /// matching Decrypt variants). False on v2.40 libraries.
    /// </summary>
    public bool IsMessageApiSupported
        => _delegates is not null
           && _delegates.HasC_MessageEncryptInit
           && _delegates.HasC_EncryptMessage
           && _delegates.HasC_MessageEncryptFinal
           && _delegates.HasC_MessageDecryptInit
           && _delegates.HasC_DecryptMessage
           && _delegates.HasC_MessageDecryptFinal;

    /// <summary>
    /// True when the loaded PKCS#11 library exposes the v3.2 surface (ML-KEM
    /// encapsulate/decapsulate, authenticated wrap/unwrap, signature-only verify, and
    /// validation-flags inspection). False on v2.40 / v3.0 / v3.1 libraries.
    /// </summary>
    public bool IsV32ApiSupported
        => _delegates is not null
           && _delegates.HasC_EncapsulateKey
           && _delegates.HasC_DecapsulateKey
           && _delegates.HasC_WrapKeyAuthenticated
           && _delegates.HasC_UnwrapKeyAuthenticated
           && _delegates.HasC_VerifySignatureInit
           && _delegates.HasC_VerifySignature
           && _delegates.HasC_GetSessionValidationFlags;

    /// <summary>
    /// Disposes object
    /// </summary>
    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes object
    /// </summary>
    /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
    private void Dispose(bool disposing)
    {
        if (_disposed) return;

        // Set the flag before unmapping the module, not after: every native entry point guards
        // with ObjectDisposedException.ThrowIf(_disposed, this) and then calls a
        // delegate* unmanaged[Cdecl] loaded from this module. Flipping the flag first means a
        // thread that reads it after this write is turned away before it can dispatch into
        // memory NativeLibrary.Free (via _library.Dispose()) is about to unmap.
        _disposed = true;

        if (disposing)
        {
            _library.Dispose();
        }
    }

    /// <summary>
    /// Class destructor that disposes object if caller forgot to do so
    /// </summary>
    ~LowLevelPkcs11Library()
    {
        Dispose(false);
    }
}
