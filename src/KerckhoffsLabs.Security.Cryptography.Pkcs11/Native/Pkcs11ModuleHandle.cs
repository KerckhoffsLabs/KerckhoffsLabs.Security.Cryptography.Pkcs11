using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Owns a loaded PKCS#11 module: its function table, its <c>C_Finalize</c>, and the OS module handle.
/// Every call into the module holds a use of this handle for its duration (see
/// <see cref="ModuleCall"/>), and every open session holds one for its lifetime, so the teardown —
/// <c>C_Finalize</c>, then <see cref="NativeLibrary.Free(IntPtr)"/> — never runs under a call or a
/// session that still needs the module.
/// </summary>
/// <remarks>
/// <para>
/// Finalizing and unmapping are separate steps. <c>C_Finalize</c> runs once it has been asked for, the
/// handle is disposed, and no use that holds it off remains. A blocking <c>C_WaitForSlotEvent</c> is the
/// one call that does not hold it off: PKCS#11 (v3.2 §5.4) has <c>C_Finalize</c> wake such a wait,
/// which then returns <c>CKR_CRYPTOKI_NOT_INITIALIZED</c>, and it is the only way to end the wait without
/// an event. The wait still holds a reference, so the module is unmapped only after the woken call
/// has left it.
/// </para>
/// <para>
/// Cryptoki state belongs to the module, not to one load of it: a second load of the same module sees
/// <c>CKR_CRYPTOKI_ALREADY_INITIALIZED</c> and shares the first's state. So a requested
/// <c>C_Finalize</c> runs only when no other load of the same module is live; otherwise it is handed to
/// the last one, which runs it on release. Loads are matched on the OS module handle (the main program
/// for a statically linked module), never on the path.
/// </para>
/// <para>
/// <c>C_Finalize</c> runs on whichever thread releases the last use that held it off: the one disposing
/// the library, a call finishing on another thread, or a session being disposed — rarely, the finalizer
/// thread. A release never calls back into the caller's code, a logger included: what happened to
/// <c>C_Finalize</c> is recorded (<see cref="FinalizeStatus"/>) for <c>Pkcs11Library.Dispose</c> to log
/// on its own thread.
/// </para>
/// <para>
/// <see cref="SafeHandle"/> is a <c>CriticalFinalizerObject</c>, so release also runs when the owner is
/// abandoned. An abandoned module that this handle initialized is not unmapped: nothing asked for its
/// <c>C_Finalize</c>, and unmapping an initialized module can pull code out from under threads it
/// started. That is a deliberate leak of the mapping, for a caller who never disposed the library.
/// </para>
/// <para>
/// Release never throws.
/// </para>
/// </remarks>
internal sealed class Pkcs11ModuleHandle : SafeHandle
{
    // Stands in for the OS handle when there is none to free (a statically linked or test module), so
    // the handle is valid and its release, which runs C_Finalize, still happens.
    private static readonly IntPtr NotLoaded = -1;

    // Every statically linked binding is the same module: the one linked into the main program.
    internal static readonly object StaticallyLinked = new();

    private static readonly Lock s_loadsLock = new();
    private static readonly Dictionary<object, Loads> s_loads = [];

    private readonly bool _freeOnRelease;
    private readonly object _identity;
    private Loads? _loads;
    private volatile bool _initialized;
    private volatile bool _finalizeOnRelease;

    // A test double has no function table; its sessions close through the double itself.
    private readonly ILowLevelPkcs11Library? _detached;

    private readonly Lock _sessionsLock = new();

    // Weak, so a session the caller disposed (or abandoned) is not kept alive by the tracker.
    private readonly List<WeakReference<Pkcs11SessionHandle>> _sessions = [];

    // Uses that hold off C_Finalize: calls in flight (bar a blocking wait) and open sessions.
    private int _finalizeHolds;

    // Set once C_Finalize has run, or been handed to another load, so it is never decided twice.
    private int _finalizeDecided;

    // Set by Dispose, before it releases. SafeHandle marks itself closed only when the last reference
    // goes, so while a call is in flight IsClosed stays false and DangerousAddRef keeps succeeding: this
    // is what turns new uses away, and what tells TryFinalize the handle was disposed.
    private int _disposed;

    /// <summary>The live loads of one module, and whether one of them owes it a <c>C_Finalize</c>.</summary>
    private sealed class Loads
    {
        public int Live;
        public bool FinalizeOwed;

        // How the module was initialized, for every load of it: a ConcurrencyMode, written by the load
        // whose C_Initialize succeeded. Not under s_loadsLock: it is set from inside a call.
        public int Mode;

        // Serializes every call into a module that may not be called concurrently (see EnterCall).
        public readonly Lock CallLock = new();
    }

    private Pkcs11ModuleHandle(IntPtr moduleHandle, bool freeOnRelease, object identity)
        : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(moduleHandle);
        _freeOnRelease = freeOnRelease;
        _identity = identity;
    }

    private Pkcs11ModuleHandle(IntPtr moduleHandle, bool freeOnRelease, ILowLevelPkcs11Library detached)
        : this(moduleHandle, freeOnRelease, identity: detached)
    {
        _detached = detached;
    }

    /// <summary>The module's function table. Only call through it while holding a use of this handle.</summary>
    internal Delegates Table { get; private set; } = null!;

    private FinalizeOutcome _finalizeOutcome;
    private CKR _finalizeReturnValue;

    /// <summary>
    /// What has happened to a requested <c>C_Finalize</c> so far, and its return value once it has run
    /// through this handle.
    /// </summary>
    internal (FinalizeOutcome Outcome, CKR ReturnValue) FinalizeStatus
    {
        get
        {
            lock (s_loadsLock)
            {
                if (_finalizeOnRelease && Volatile.Read(ref _finalizeDecided) == 0)
                    return (FinalizeOutcome.Deferred, default);
                return (_finalizeOutcome, _finalizeReturnValue);
            }
        }
    }

    /// <summary>Loads the module at <paramref name="libraryPath"/> and binds its function table.</summary>
    internal static Pkcs11ModuleHandle Load(string libraryPath)
    {
        IntPtr loaded = NativeLibrary.Load(libraryPath);
        return Bound(new Pkcs11ModuleHandle(loaded, freeOnRelease: true, identity: loaded), () => new Delegates(loaded));
    }

    /// <summary>
    /// Binds a module this handle does not load, and so never frees: statically linked, or a test module.
    /// </summary>
    /// <param name="bind">Builds the function table.</param>
    /// <param name="identity">
    /// Which module this is, so two bindings of it share its Cryptoki state; <see langword="null"/> for a
    /// binding that shares with nothing.
    /// </param>
    internal static Pkcs11ModuleHandle Bind(Func<Delegates> bind, object? identity = null)
        => Bound(new Pkcs11ModuleHandle(NotLoaded, freeOnRelease: false, identity ?? new object()), bind);

    private static Pkcs11ModuleHandle Bound(Pkcs11ModuleHandle module, Func<Delegates> bind)
    {
        try
        {
            module.Table = bind();
        }
        catch
        {
            module.Dispose();
            throw;
        }

        lock (s_loadsLock)
        {
            if (!s_loads.TryGetValue(module._identity, out Loads? loads))
                s_loads[module._identity] = loads = new Loads();
            loads.Live++;
            module._loads = loads;
        }
        return module;
    }

    /// <summary>
    /// Takes a use of this handle; throws <see cref="ObjectDisposedException"/> once it is disposed.
    /// </summary>
    /// <param name="added">Set when the use was taken, and so must be returned with <see cref="ReleaseUse"/>.</param>
    /// <param name="holdsOffFinalize">
    /// <see langword="false"/> only for a blocking <c>C_WaitForSlotEvent</c>, which <c>C_Finalize</c> is
    /// meant to wake (see remarks).
    /// </param>
    internal void AddUse(ref bool added, bool holdsOffFinalize = true)
    {
        DangerousAddRef(ref added);
        if (!added)
            return;
        if (holdsOffFinalize)
            Interlocked.Increment(ref _finalizeHolds);

        // Read after taking the use, and Dispose writes before it reads the holds (both full fences): so
        // either this sees the dispose and backs out, or TryFinalize sees this use and leaves C_Finalize
        // to its release.
        if (Volatile.Read(ref _disposed) != 0)
        {
            added = false;
            ReleaseUse(holdsOffFinalize);
            throw new ObjectDisposedException(GetType().FullName);
        }
    }

    /// <summary>Returns a use taken by <see cref="AddUse"/>.</summary>
    internal void ReleaseUse(bool holdsOffFinalize = true)
    {
        // Finalize first, while this use still keeps the module mapped.
        if (holdsOffFinalize && Interlocked.Decrement(ref _finalizeHolds) == 0)
            TryFinalize();
        DangerousRelease();
    }

    /// <summary>
    /// A handle for a test double: no module to load, finalize or free, but sessions are tracked and
    /// referenced exactly as for a real module, and close through <paramref name="library"/>.
    /// </summary>
    internal static Pkcs11ModuleHandle Detached(ILowLevelPkcs11Library library)
        => new(NotLoaded, freeOnRelease: false, library);

    /// <summary>Closes <paramref name="session"/>. The caller holds a reference on this handle.</summary>
    internal CKR CloseSession(NativeCULong session)
    {
        if (_detached is not null)
            return _detached.C_CloseSession(session);
        bool serialized = EnterCall();
        try
        {
            return Table.C_CloseSession(session).ToCKR();
        }
        finally
        {
            if (serialized)
                ExitCall();
        }
    }

    /// <summary>
    /// Whether the module may be called from several threads at once: it was initialized with
    /// <c>CKF_OS_LOCKING_OK</c>, by this load or another load of it. <see langword="false"/> when it
    /// refused OS locking (<c>CKR_CANT_LOCK</c>) and was initialized without it — a promise, under
    /// PKCS#11 v3.2 §5.4, that it will not be — and also when it was initialized by something other than
    /// this library, in a way that is not known.
    /// </summary>
    internal bool SupportsConcurrentAccess
        => _detached is not null
           || (_loads is not null && (ConcurrencyMode)Volatile.Read(ref _loads.Mode) == ConcurrencyMode.OsLocking);

    /// <summary>
    /// Takes the module-wide call lock unless the module may be called concurrently; returns whether
    /// it did, for <see cref="ExitCall"/>. Every call into the module goes through here, from every load
    /// of it, which is what keeps the promise a single-threaded <c>C_Initialize</c> makes.
    /// </summary>
    /// <remarks>
    /// Lock order: s_loadsLock, then the call lock, never the reverse. Nothing that holds the call lock
    /// takes s_loadsLock.
    /// </remarks>
    internal bool EnterCall()
    {
        if (SupportsConcurrentAccess || _loads is null)
            return false;
        _loads.CallLock.Enter();
        return true;
    }

    /// <summary>Releases the call lock taken by <see cref="EnterCall"/>.</summary>
    internal void ExitCall() => _loads!.CallLock.Exit();

    /// <summary>Count of still-live tracked sessions (test/diagnostic seam).</summary>
    internal int TrackedSessionCount
    {
        get
        {
            lock (_sessionsLock)
            {
                _sessions.RemoveAll(wr => !wr.TryGetTarget(out _));
                return _sessions.Count;
            }
        }
    }

    /// <summary>Tracks <paramref name="session"/> so <see cref="CloseAllTrackedSessions"/> can close it.</summary>
    internal void Track(Pkcs11SessionHandle session)
    {
        lock (_sessionsLock)
        {
            _sessions.RemoveAll(wr => !wr.TryGetTarget(out _));
            _sessions.Add(new WeakReference<Pkcs11SessionHandle>(session));
        }
    }

    /// <summary>Stops tracking <paramref name="session"/>, after it has closed.</summary>
    internal void Untrack(Pkcs11SessionHandle session)
    {
        lock (_sessionsLock)
            _sessions.RemoveAll(wr => !wr.TryGetTarget(out var h) || ReferenceEquals(h, session));
    }

    /// <summary>
    /// Closes every still-live tracked session. A session with an operation in flight holds a reference
    /// on its handle, so its <c>C_CloseSession</c> waits for that operation to finish.
    /// <see cref="SafeHandle.Dispose()"/> is reentrant and thread-safe, so a caller disposing the same
    /// session on another thread is harmless.
    /// </summary>
    internal void CloseAllTrackedSessions()
    {
        Pkcs11SessionHandle[] live;
        lock (_sessionsLock)
        {
            live = [.. _sessions.Select(wr => wr.TryGetTarget(out var h) ? h : null).OfType<Pkcs11SessionHandle>()];
            _sessions.Clear();
        }

        // A session's release never throws: a C_CloseSession that fails, or throws, is reported by its
        // ReleaseHandle returning false, which Dispose ignores. So one bad handle cannot keep the others open.
        foreach (var session in live.Where(s => !s.IsClosed && !s.IsInvalid))
            session.Dispose();
    }

    /// <summary>
    /// Records that <c>C_Initialize</c> through this handle succeeded, and whether it asked for OS locking
    /// (<c>CKF_OS_LOCKING_OK</c>), for every load of the module to see.
    /// </summary>
    internal void MarkInitialized(bool osLocking)
    {
        _initialized = true;
        if (_loads is not null)
            Volatile.Write(ref _loads.Mode, (int)(osLocking ? ConcurrencyMode.OsLocking : ConcurrencyMode.SingleThreaded));
    }

    /// <summary>Records that <c>C_Finalize</c> through this handle succeeded.</summary>
    internal void MarkFinalized()
    {
        _initialized = false;
        _finalizeOnRelease = false;
        lock (s_loadsLock)
        {
            if (_loads is not null)
            {
                _loads.FinalizeOwed = false;
                Volatile.Write(ref _loads.Mode, (int)ConcurrencyMode.Unknown);
            }
        }
    }

    /// <summary>
    /// Asks for <c>C_Finalize</c> once this handle is disposed and nothing holds it off any more, rather
    /// than now, so it cannot run under a call or a session that still needs the module.
    /// </summary>
    internal void FinalizeOnRelease()
    {
        if (_initialized)
            _finalizeOnRelease = true;
    }

    /// <inheritdoc/>
    public override bool IsInvalid => handle == IntPtr.Zero;

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        Interlocked.Exchange(ref _disposed, 1);
        base.Dispose(disposing);
        // Only blocking waits may still hold references: C_Finalize is due now, and wakes them.
        TryFinalize();
    }

    private void TryFinalize()
    {
        if (!_finalizeOnRelease || Volatile.Read(ref _disposed) == 0 || Volatile.Read(ref _finalizeHolds) != 0)
            return;
        if (Interlocked.Exchange(ref _finalizeDecided, 1) != 0)
            return;

        // Under the lock, so a load of the same module cannot slip in between this decision and the
        // C_Finalize: it either counts as live here, or initializes afresh once this has finalized.
        lock (s_loadsLock)
        {
            if (_loads is { Live: > 1 })
            {
                _loads.FinalizeOwed = true; // another load still uses the module; the last one finalizes
                _finalizeOutcome = FinalizeOutcome.HandedOff;
            }
            else
            {
                RunFinalize();
            }
        }
    }

    /// <inheritdoc/>
    protected override bool ReleaseHandle()
    {
        TryFinalize();

        bool finalizedForOthers = false;
        lock (s_loadsLock)
        {
            if (_loads is not null && --_loads.Live == 0)
            {
                if (_loads.FinalizeOwed)
                {
                    RunFinalize();
                    finalizedForOthers = true;
                }
                s_loads.Remove(_identity);
            }
        }

        if (_initialized && !_finalizeOnRelease && !finalizedForOthers)
            return true; // abandoned while initialized: never unmap it (see remarks)

        if (!_freeOnRelease)
            return true;
        // Documented to throw nothing: the runtime ignores what dlclose/FreeLibrary return.
        NativeLibrary.Free(handle);
        return true;
    }

    // Always under s_loadsLock.
    private void RunFinalize()
    {
        // Nothing may escape a release, and the wrapper's only managed exception is the one for an
        // unbound function, so check that instead of catching it.
        if (!Table.HasC_Finalize)
            return;
        bool serialized = EnterCall();
        try
        {
            _finalizeReturnValue = Table.C_Finalize(IntPtr.Zero).ToCKR();
        }
        finally
        {
            if (serialized)
                ExitCall();
        }
        _finalizeOutcome = _finalizeReturnValue == CKR.CKR_OK ? FinalizeOutcome.Succeeded : FinalizeOutcome.Failed;
    }
}

/// <summary>How a module was initialized, as far as its calls' concurrency goes.</summary>
internal enum ConcurrencyMode
{
    /// <summary>Not initialized by this library: its threading mode is not known, so calls are serialized.</summary>
    Unknown,

    /// <summary>Initialized with <c>CKF_OS_LOCKING_OK</c>: the module locks for itself.</summary>
    OsLocking,

    /// <summary>Initialized without OS locking, after <c>CKR_CANT_LOCK</c>: it must never be called concurrently.</summary>
    SingleThreaded,
}

/// <summary>What has happened to a requested <c>C_Finalize</c>.</summary>
internal enum FinalizeOutcome
{
    /// <summary>Not requested, or the module binds no <c>C_Finalize</c>.</summary>
    None,

    /// <summary>Waiting for a call in flight or an open session to release the module.</summary>
    Deferred,

    /// <summary>Left to another load of the same module, which is still live and finalizes when it goes.</summary>
    HandedOff,

    /// <summary>Ran and returned <c>CKR_OK</c>.</summary>
    Succeeded,

    /// <summary>Ran and returned an error.</summary>
    Failed,
}
