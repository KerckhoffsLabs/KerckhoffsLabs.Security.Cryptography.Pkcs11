using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The login state of one module, shared by every load of it: one <see cref="TokenLoginRecord"/> per slot,
/// and a tally of the sessions the library has open on each slot, by access.
/// </summary>
/// <remarks>
/// <para>
/// PKCS#11 v3.2 makes login state belong to the application and the token, shared by all the application's
/// sessions with it, and the "application" is the Cryptoki instance in the process: a second load of the same
/// module shares the first's state. So the records are kept per module (<see cref="Pkcs11ModuleHandle.Shared{T}"/>)
/// rather than per <see cref="Pkcs11Library"/>, and start empty again after the module's <c>C_Finalize</c>. The PINs the
/// module's tokens refused do not: they are kept for the life of the process (<see cref="RefusedPinsFor"/>).
/// </para>
/// <para>
/// The session tally is what lets the library refuse, before the module, what the spec forbids from state it
/// owns: an SO login while it has a read-only session open on the slot, and the like. Sessions opened outside
/// the library are not counted; the module's own answer covers those.
/// </para>
/// </remarks>
internal sealed class TokenLoginRegistry : Pkcs11ModuleHandle.IUnloadAware
{
    private readonly Lock _lock = new();
    private readonly Dictionary<ulong, TokenLoginRecord> _records = [];
    private readonly Dictionary<ulong, (int ReadOnly, int ReadWrite)> _sessions = [];

    /// <summary>
    /// The login records of <paramref name="module"/>, shared by every load of it until its next
    /// <c>C_Finalize</c>.
    /// </summary>
    /// <remarks>
    /// Kept by the Native layer (<see cref="Pkcs11ModuleHandle.Shared{T}"/>), which may not depend on this
    /// one, so reached from here rather than as a member of the module handle.
    /// </remarks>
    public static TokenLoginRegistry Of(Pkcs11ModuleHandle module)
    {
        ArgumentNullException.ThrowIfNull(module);
        TokenLoginRegistry registry = module.Shared<TokenLoginRegistry>();
        // Before any record is made: a record takes its slot's refused PINs from here.
        if (Volatile.Read(ref registry._refusedPins) is null)
            Interlocked.CompareExchange(ref registry._refusedPins, module.Durable<RefusedPinsBySlot>(), null);
        if (Volatile.Read(ref registry._carried) is null)
        {
            Interlocked.CompareExchange(ref registry._finalizations, module.Finalizations, null);
            Interlocked.CompareExchange(ref registry._carried, module.Durable<LeftBehindBySlot>(), null);
        }
        return registry;
    }

    // The logins records left on the token when the module's last load was released without C_Finalize (another
    // component keeps it initialized), per slot: the next registry's records start with them, so their own login is
    // logged out rather than refused as foreign (TokenLoginRecord's left-behind login). Kept with how many times the
    // module was finalized through this library, and dropped once that changed: a finalization ended them.
    private LeftBehindBySlot? _carried;
    private Pkcs11ModuleHandle.FinalizeCount? _finalizations;

    /// <summary>Logins left on the module's tokens, carried from one registry of the module to the next.</summary>
    internal sealed class LeftBehindBySlot
    {
        private readonly Lock _lock = new();
        private readonly Dictionary<ulong, (TokenUser User, long Finalizations)> _slots = [];

        public void Put(ulong slotId, TokenUser user, long finalizations)
        {
            lock (_lock)
                _slots[slotId] = (user, finalizations);
        }

        public TokenUser? Take(ulong slotId, long finalizations)
        {
            lock (_lock)
            {
                if (!_slots.Remove(slotId, out var carried) || carried.Finalizations != finalizations)
                    return null;
                return carried.User;
            }
        }
    }

    /// <summary>
    /// The module's last load released, so this registry is dropped: the logins its records left on the token are
    /// carried to the next registry of the module (<see cref="LeftBehindBySlot"/>).
    /// </summary>
    public void Unloaded()
    {
        if (Volatile.Read(ref _carried) is not { } carried || _finalizations is not { } finalizations)
            return;
        long count = finalizations.Value;
        foreach (TokenLoginRecord record in Records())
        {
            if (record.LeftBehindUser is { } user)
                carried.Put((ulong)record.SlotId, user, count);
        }
    }

    // The PINs the module's tokens refused, per slot: kept for the life of the process, across C_Finalize and the
    // module's unloading (Pkcs11ModuleHandle.Durable), unlike the login records, so that code loading the module per
    // request does not start each request with none.
    private RefusedPinsBySlot? _refusedPins;

    /// <summary>The PINs refused on <paramref name="slotId"/>'s tokens, kept for the life of the process.</summary>
    internal RefusedPins RefusedPinsFor(NativeCULong slotId)
        => (Volatile.Read(ref _refusedPins) ?? throw new InvalidOperationException("No module.")).For(slotId);

    /// <summary>The refused PINs of one module, per slot, for the life of the process.</summary>
    internal sealed class RefusedPinsBySlot
    {
        private readonly System.Collections.Concurrent.ConcurrentDictionary<ulong, RefusedPins> _slots = new();

        public RefusedPins For(NativeCULong slotId) => _slots.GetOrAdd((ulong)slotId, static _ => new RefusedPins());
    }

    /// <summary>The login record of <paramref name="slotId"/>, created on first use; always the same one.</summary>
    public TokenLoginRecord For(NativeCULong slotId)
    {
        lock (_lock)
        {
            if (!_records.TryGetValue((ulong)slotId, out TokenLoginRecord? record))
            {
                _records[(ulong)slotId] = record = new TokenLoginRecord(slotId, this);
                if (_finalizations is { } finalizations
                    && Volatile.Read(ref _carried)?.Take((ulong)slotId, finalizations.Value) is { } user)
                {
                    record.CarryLeftBehind(user);
                }
            }
            return record;
        }
    }

    /// <summary>Every login record made so far, for a library's disposal to release its holders in each.</summary>
    public TokenLoginRecord[] Records()
    {
        lock (_lock)
            return [.. _records.Values];
    }

    // The loads of the module alive, held weakly: one that is never disposed is not kept alive by this.
    private readonly List<WeakReference<Pkcs11Library>> _libraries = [];

    /// <summary>Records <paramref name="library"/>, a load of the module, as alive.</summary>
    public void LibraryOpened(Pkcs11Library library)
    {
        lock (_lock)
            _libraries.Add(new WeakReference<Pkcs11Library>(library));
    }

    /// <summary>Stops offering <paramref name="library"/>, whose disposal has begun.</summary>
    public void LibraryClosing(Pkcs11Library library)
    {
        lock (_lock)
            _libraries.RemoveAll(load => !load.TryGetTarget(out Pkcs11Library? alive) || ReferenceEquals(alive, library));
    }

    /// <summary>
    /// A load of the module not being disposed, or <see langword="null"/>: for a logout left on the token once the load
    /// that made the login is gone.
    /// </summary>
    public Pkcs11Library? LiveLibrary()
    {
        lock (_lock)
        {
            foreach (WeakReference<Pkcs11Library> load in _libraries)
            {
                if (load.TryGetTarget(out Pkcs11Library? alive) && !alive.IsDisposingOrDisposed)
                    return alive;
            }
            return null;
        }
    }

    /// <summary>Counts a session the library opened on <paramref name="slotId"/>.</summary>
    public void SessionOpened(NativeCULong slotId, SessionAccess access)
    {
        lock (_lock)
        {
            (int readOnly, int readWrite) = _sessions.GetValueOrDefault((ulong)slotId);
            _sessions[(ulong)slotId] = access == SessionAccess.ReadWrite ? (readOnly, readWrite + 1) : (readOnly + 1, readWrite);
        }
    }

    /// <summary>Stops counting a session counted by <see cref="SessionOpened"/>, once it has closed.</summary>
    public void SessionClosed(NativeCULong slotId, SessionAccess access)
    {
        lock (_lock)
        {
            (int readOnly, int readWrite) = _sessions.GetValueOrDefault((ulong)slotId);
            (readOnly, readWrite) = access == SessionAccess.ReadWrite
                ? (readOnly, Math.Max(0, readWrite - 1))
                : (Math.Max(0, readOnly - 1), readWrite);
            if (readOnly == 0 && readWrite == 0)
                _sessions.Remove((ulong)slotId);
            else
                _sessions[(ulong)slotId] = (readOnly, readWrite);
        }
    }

    /// <summary>The sessions the library has open on <paramref name="slotId"/>, through any load of the module.</summary>
    public (int ReadOnly, int ReadWrite) Sessions(NativeCULong slotId)
    {
        lock (_lock)
            return _sessions.GetValueOrDefault((ulong)slotId);
    }
}
