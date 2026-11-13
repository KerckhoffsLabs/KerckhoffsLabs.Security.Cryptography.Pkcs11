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
/// rather than per <see cref="Pkcs11Library"/>, and start empty again after the module's <c>C_Finalize</c>.
/// </para>
/// <para>
/// The session tally is what lets the library refuse, before the module, what the spec forbids from state it
/// owns: an SO login while it has a read-only session open on the slot, and the like. Sessions opened outside
/// the library are not counted; the module's own answer covers those.
/// </para>
/// </remarks>
internal sealed class TokenLoginRegistry
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
        return module.Shared<TokenLoginRegistry>();
    }

    /// <summary>The login record of <paramref name="slotId"/>, created on first use; always the same one.</summary>
    public TokenLoginRecord For(NativeCULong slotId)
    {
        lock (_lock)
        {
            if (!_records.TryGetValue((ulong)slotId, out TokenLoginRecord? record))
                _records[(ulong)slotId] = record = new TokenLoginRecord(slotId);
            return record;
        }
    }

    /// <summary>Every login record made so far, for a library's disposal to release its holders in each.</summary>
    public TokenLoginRecord[] Records()
    {
        lock (_lock)
            return [.. _records.Values];
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
