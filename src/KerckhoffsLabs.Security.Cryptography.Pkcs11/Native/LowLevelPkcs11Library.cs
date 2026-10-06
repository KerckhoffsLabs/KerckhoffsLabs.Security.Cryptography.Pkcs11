using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library : ILowLevelPkcs11Library
{

    /// <summary>
    /// The loaded module. It owns the function table, so a call can reach the module only while it holds
    /// a reference on this handle (<see cref="EnterModule"/>), and <c>C_Finalize</c> and the unmap wait
    /// for the last such reference.
    /// </summary>
    private readonly Pkcs11ModuleHandle _module;

    /// <summary>
    /// The module handle, exposed so <see cref="Internal.SafeHandles.Pkcs11SessionHandle"/> can take
    /// a <c>DangerousAddRef</c> on it for the session's lifetime — the CLR gives no ordering
    /// guarantee between two independent <c>CriticalFinalizerObject</c>s, so without an explicit
    /// SafeHandle ref count this module could be unmapped before an abandoned session's
    /// <c>C_CloseSession</c> runs.
    /// </summary>
    internal Pkcs11ModuleHandle ModuleHandle => _module;

    /// <summary>
    /// A use of the module for one call. Throws <see cref="ObjectDisposedException"/> once this
    /// library has been disposed; there is no window between that check and the call, because the
    /// use itself keeps the module from being finalized or unmapped.
    /// </summary>
    /// <param name="holdsOffFinalize"><see langword="false"/> only for a blocking <c>C_WaitForSlotEvent</c>.</param>
    private ModuleCall EnterModule(bool holdsOffFinalize = true) => new(_module, holdsOffFinalize);

    /// <summary>What has happened to a requested <c>C_Finalize</c> so far.</summary>
    internal (FinalizeOutcome Outcome, CKR ReturnValue) FinalizeStatus => _module.FinalizeStatus;

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
        _module = Pkcs11ModuleHandle.Load(libraryPath);
    }

    /// <summary>
    /// Binds to a statically-linked PKCS#11 implementation. The cryptoki symbols are expected to be
    /// linked into the host executable and exported from it, so <c>C_GetFunctionList</c> resolves
    /// against the entry-point module's own symbol table. All subsequent calls go through the
    /// returned function-pointer table, same as the dynamic-load path.
    /// </summary>
    internal LowLevelPkcs11Library()
        : this(() => new Delegates(IntPtr.Zero), Pkcs11ModuleHandle.StaticallyLinked)
    {
    }

    /// <summary>
    /// Binds to a module whose exports come from <paramref name="resolveExport"/> rather than from a
    /// loaded library. This is the test seam: a test hands in a module built from managed
    /// <c>[UnmanagedCallersOnly]</c> functions, and every call then goes through the same loader,
    /// wrappers, pinning and struct packing as a real module.
    /// </summary>
    /// <param name="resolveExport">Maps an export name to its address, or <see cref="IntPtr.Zero"/> when absent.</param>
    internal LowLevelPkcs11Library(Func<string, IntPtr> resolveExport)
        : this(() => new Delegates(resolveExport), resolveExport.Target ?? resolveExport)
    {
    }

    // identity: which module this is, so two bindings of the same one share its Cryptoki state. A test
    // module is identified by the object whose method resolves its exports.
    private LowLevelPkcs11Library(Func<Delegates> bind, object identity)
    {
        EnsureCkUlongWidthMatchesPlatform();
        _module = Pkcs11ModuleHandle.Bind(bind, identity);
    }

    /// <summary>
    /// Verifies the resolved build's CK_ULONG width (<see cref="NativeCULong"/>) matches the
    /// host's native CK_ULONG: 4 bytes on Windows (LLP64), the pointer width on Unix (LP64/ILP32).
    /// KerckhoffsLabs.Runtime.InteropServices ships <see cref="NativeCULong"/> as <c>nuint</c> in its
    /// <c>lib/net10.0</c> assembly and as <c>uint</c> in its <c>runtimes/win-x64</c> and
    /// <c>runtimes/win-arm64</c> assets, so 64-bit Windows running the <c>lib</c> assembly (8 bytes)
    /// would silently mis-marshal every CK_ULONG-bearing struct. Fail loudly instead: the
    /// runtime-specific asset was not resolved.
    /// </summary>
    private static void EnsureCkUlongWidthMatchesPlatform()
    {
        int expected = OperatingSystem.IsWindows() ? sizeof(uint) : IntPtr.Size;
        // Unsafe.SizeOf, not Marshal.SizeOf: what can mis-marshal is the by-value CK_ULONG in the
        // delegate* unmanaged[Cdecl] signatures, and [assembly: DisableRuntimeMarshalling] makes those
        // use the blittable layout. NativeCULong wraps a single primitive so the two sizes agree, but
        // this guard should measure the layout that actually crosses the boundary.
        int actual = Unsafe.SizeOf<NativeCULong>();
        ThrowIfWidthMismatch(actual, expected);
    }

    /// <summary>
    /// The actual throw condition behind <see cref="EnsureCkUlongWidthMatchesPlatform"/>, split out
    /// as a pure function so the mismatch branch is testable without an actually-mismatched build:
    /// a correctly-built test run can never observe <paramref name="actual"/> != <paramref name="expected"/>
    /// from <see cref="EnsureCkUlongWidthMatchesPlatform"/> itself.
    /// </summary>
    internal static void ThrowIfWidthMismatch(int actual, int expected)
    {
        if (actual != expected)
        {
            throw new PlatformNotSupportedException(
                $"CK_ULONG width mismatch: NativeCULong is {actual} bytes but the native CK_ULONG on " +
                $"this platform is {expected} bytes. The runtime-specific KerckhoffsLabs.Runtime.InteropServices " +
                "assembly for this platform was not loaded. Deploy the application's .deps.json with it, or " +
                "restore and publish with a RuntimeIdentifier, and check that no version of " +
                "KerckhoffsLabs.Runtime.InteropServices older than 1.2.0 is referenced or overrides it.");
        }
    }

    /// <summary>
    /// True when the loaded PKCS#11 library exposes the v3.0 message-based AEAD
    /// functions (C_MessageEncryptInit / C_EncryptMessage / C_MessageEncryptFinal +
    /// matching Decrypt variants). False on v2.40 libraries.
    /// </summary>
    public bool IsMessageApiSupported
        => _module.Table.HasC_MessageEncryptInit
           && _module.Table.HasC_EncryptMessage
           && _module.Table.HasC_MessageEncryptFinal
           && _module.Table.HasC_MessageDecryptInit
           && _module.Table.HasC_DecryptMessage
           && _module.Table.HasC_MessageDecryptFinal;

    /// <summary>
    /// True when the loaded PKCS#11 library exposes the v3.2 surface (ML-KEM
    /// encapsulate/decapsulate, authenticated wrap/unwrap, signature-only verify, and
    /// validation-flags inspection). False on v2.40 / v3.0 / v3.1 libraries.
    /// </summary>
    public bool IsV32ApiSupported
        => _module.Table.HasC_EncapsulateKey
           && _module.Table.HasC_DecapsulateKey
           && _module.Table.HasC_WrapKeyAuthenticated
           && _module.Table.HasC_UnwrapKeyAuthenticated
           && _module.Table.HasC_VerifySignatureInit
           && _module.Table.HasC_VerifySignature
           && _module.Table.HasC_GetSessionValidationFlags;

    /// <summary>
    /// Asks for <c>C_Finalize</c> on the module's last release instead of now. A call still in flight, or
    /// a session still open, holds a reference, so the module is finalized only once nothing is using it.
    /// Has no effect unless <c>C_Initialize</c> through this library succeeded.
    /// </summary>
    public void FinalizeOnLastRelease() => _module.FinalizeOnRelease();

    /// <summary>
    /// Releases this library's reference on the module. Calls that begin afterwards throw
    /// <see cref="ObjectDisposedException"/>; one already in flight completes, and the module is
    /// finalized (if requested) and unmapped when it, and every session, has released its reference.
    /// </summary>
    public void Dispose() => _module.Dispose();
}
