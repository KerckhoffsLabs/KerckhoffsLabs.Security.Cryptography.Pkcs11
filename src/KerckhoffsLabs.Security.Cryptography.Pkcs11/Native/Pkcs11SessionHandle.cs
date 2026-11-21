using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// <see cref="SafeHandle"/> wrapper around a PKCS#11 session handle. Calls
/// <c>C_CloseSession</c> on release, and holds a reference on its <see cref="Pkcs11ModuleHandle"/>
/// for its whole lifetime so the module cannot be finalized or unmapped while the session is open.
/// </summary>
/// <remarks>
/// Mere GC reachability does not order this: <see cref="SafeHandle"/> is a
/// <c>CriticalFinalizerObject</c>, and the CLR gives no relative ordering guarantee between two
/// independent critical finalizers. The explicit use of the module (<c>AddUse</c>), released last in
/// <see cref="ReleaseHandle"/>, is what defers the module's release until this handle's
/// <c>C_CloseSession</c> has run.
/// </remarks>
internal sealed class Pkcs11SessionHandle : SafeHandle
{
    private readonly Pkcs11ModuleHandle _module;

    /// <summary>Whether the use of <see cref="_module"/> was taken and must be released.</summary>
    private readonly bool _moduleRefAdded;

    /// <summary>
    /// The session id, held here rather than in the base handle field. <c>CK_SESSION_HANDLE</c> is
    /// an opaque <c>CK_ULONG</c> whose entire unsigned range is legal — modules deriving handles
    /// from pointers or hash tables do set the high bit — while <see cref="IntPtr"/> is signed and
    /// pointer-width. Round-tripping through it would need a conversion that is lossy on some RIDs
    /// and, because this assembly builds with <c>CheckForOverflowUnderflow</c>, throwing on others:
    /// on win-x86 every handle from <c>0x8000_0000</c> up, elsewhere every one from
    /// <c>0x8000_0000_0000_0000</c> up. Storing the id in its own field removes the conversion
    /// rather than making it clever.
    /// </summary>
    private readonly NativeCULong _sessionId;

    /// <summary>Run once, at the end of the release; see the constructor.</summary>
    private readonly Action? _released;

    /// <summary>Creates a session handle. The handle is invalid if <paramref name="sessionId"/> is <see cref="CK.CK_INVALID_HANDLE"/>.</summary>
    /// <param name="library">The load of the module the session was opened through.</param>
    /// <param name="sessionId">The session's handle.</param>
    /// <param name="slotId">The slot the session was opened on.</param>
    /// <param name="isReadWrite">Whether the session was opened with <c>CKF_RW_SESSION</c>.</param>
    /// <param name="isAnchor">Whether the session is a token login's anchor; see <see cref="IsAnchor"/>.</param>
    /// <param name="released">
    /// Run exactly once when a valid handle is released, however that comes about (its owner's disposal,
    /// <see cref="Pkcs11ModuleHandle.CloseAllTrackedSessions"/>, the finalizer), after <c>C_CloseSession</c>: what
    /// lets the layer above keep count of the open sessions without this layer knowing it. It must not throw;
    /// anything it throws is swallowed, since a release may not throw.
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="library"/> is null.</exception>
    public Pkcs11SessionHandle(LowLevelPkcs11Library library, NativeCULong sessionId, NativeCULong slotId = default,
        bool isReadWrite = false, bool isAnchor = false, Action? released = null)
        : base(IntPtr.Zero, ownsHandle: true)
    {
        ArgumentNullException.ThrowIfNull(library);
        _module = library.Module;
        _sessionId = sessionId;
        SlotId = slotId;
        IsReadWrite = isReadWrite;
        IsAnchor = isAnchor;
        _released = released;

        if (!IsInvalid)
        {
            // A use that holds off C_Finalize: the module is not finalized under an open session.
            _module.AddUse(ref _moduleRefAdded);
            // Tracked so Pkcs11Library.Dispose can close it before asking for C_Finalize.
            _module.Track(this);
        }
    }

    /// <summary>The underlying PKCS#11 session handle.</summary>
    public NativeCULong SessionId => _sessionId;

    /// <summary>The slot the session was opened on.</summary>
    public NativeCULong SlotId { get; }

    /// <summary>Whether the session is read/write (<c>CKF_RW_SESSION</c>) rather than read-only.</summary>
    public bool IsReadWrite { get; }

    /// <summary>
    /// Whether this is the anchor session of a token login, which every load of the module shares: it is left
    /// open by <see cref="Pkcs11ModuleHandle.CloseAllTrackedSessions"/>, and closed by the login once its last
    /// holder goes.
    /// </summary>
    public bool IsAnchor { get; }

    /// <summary>Set once the module has said this session no longer exists; see <see cref="MarkClosedByModule"/>.</summary>
    private volatile bool _closedByModule;

    /// <summary>
    /// Records that the module answered <c>CKR_SESSION_CLOSED</c> or <c>CKR_SESSION_HANDLE_INVALID</c> for this
    /// session: it is already closed, and the module may give its number to a session opened since, which a
    /// <c>C_CloseSession</c> here would close. The release then skips that call but still untracks the handle and
    /// releases its use of the module, so <c>C_Finalize</c> is not held off.
    /// </summary>
    internal void MarkClosedByModule() => _closedByModule = true;

    /// <inheritdoc/>
    public override bool IsInvalid => (ulong)_sessionId == CK.CK_INVALID_HANDLE;

    /// <inheritdoc/>
    protected override bool ReleaseHandle()
    {
        try
        {
            if (IsInvalid) return true;
            try
            {
                if (_closedByModule)
                    return true;

                // Through the module, not the library: the library may already be disposed (an
                // abandoned session's finalizer runs in any order relative to the library's), but this
                // handle's reference keeps the module mapped for the call.
                return _module.CloseSession(SessionId) == CKR.CKR_OK;
            }
            catch
            {
                return false;
            }
            finally
            {
                // Prune the tracker entry so it does not grow for long-running consumers that open
                // and close many sessions.
                _module.Untrack(this);
            }
        }
        finally
        {
            try
            {
                _released?.Invoke();
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // Contained: a release may not throw (it can run on the finalizer thread, where an exception ends
                // the process), so anything else the callback throws is dropped; see the constructor. The one
                // callback passed (TokenLoginRegistry.SessionClosed) only updates a tally under a lock. An
                // OutOfMemoryException is knowingly let through, as the process is failing anyway; the module's
                // use is still released, once, by the finally below.
            }
            finally
            {
                // Release last: only after C_CloseSession has had its chance to run does the module
                // become eligible for its own SafeHandle release.
                if (_moduleRefAdded) _module.ReleaseUse();
            }
        }
    }
}
