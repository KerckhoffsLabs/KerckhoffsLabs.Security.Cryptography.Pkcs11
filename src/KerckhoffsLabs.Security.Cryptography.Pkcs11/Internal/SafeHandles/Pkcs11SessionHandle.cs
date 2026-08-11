using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;

/// <summary>
/// <see cref="SafeHandle"/> wrapper around a PKCS#11 session handle. Calls
/// <c>C_CloseSession</c> on release. Holds a reference to the owning
/// <see cref="LowLevelPkcs11Library"/> so the library SafeHandle cannot be released
/// while any session is still open.
/// </summary>
/// <remarks>
/// The library reference enforces a GC reachability invariant: as long as this
/// SafeHandle is alive, the <see cref="LowLevelPkcs11Library"/> and its
/// <see cref="Pkcs11ModuleHandle"/> remain reachable. This guarantees that
/// <c>C_CloseSession</c> can still be called when this handle is finally released.
/// </remarks>
internal sealed class Pkcs11SessionHandle : SafeHandle
{
    /// <summary>
    /// Opaque non-zero value parked in the base <see cref="SafeHandle.handle"/> field for a live
    /// session. It is a presence flag, never dereferenced and never sent to the module — the real
    /// id lives in <see cref="_sessionId"/>. Keeping it non-zero means
    /// <see cref="SafeHandle.DangerousGetHandle"/> and a debugger agree with
    /// <see cref="IsInvalid"/> about whether this instance owns something.
    /// </summary>
    private static readonly IntPtr LiveSessionMarker = 1;

    private readonly ILowLevelPkcs11Library _library;

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

    /// <summary>Creates a session handle. The handle is invalid if <paramref name="sessionId"/> is <see cref="CK.CK_INVALID_HANDLE"/>.</summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="library"/> is null.</exception>
    public Pkcs11SessionHandle(ILowLevelPkcs11Library library, NativeCULong sessionId)
        : base(IntPtr.Zero, ownsHandle: true)
    {
        ArgumentNullException.ThrowIfNull(library);
        _library = library;
        _sessionId = sessionId;
        if ((ulong)sessionId != CK.CK_INVALID_HANDLE)
            SetHandle(LiveSessionMarker);
        // Register with the library so Pkcs11Library.Dispose can close us before C_Finalize
        // unloads the function table.
        _library.RegisterSession(this);
    }

    /// <summary>The underlying PKCS#11 session handle.</summary>
    public NativeCULong SessionId => _sessionId;

    /// <inheritdoc/>
    public override bool IsInvalid => (ulong)_sessionId == CK.CK_INVALID_HANDLE;

    /// <inheritdoc/>
    protected override bool ReleaseHandle()
    {
        if (IsInvalid) return true;
        try
        {
            CKR rv = _library.C_CloseSession(SessionId);
            return rv == CKR.CKR_OK;
        }
        catch
        {
            return false;
        }
        finally
        {
            // Best-effort: prune our tracker entry so the library's tracker doesn't grow
            // unbounded for long-running consumers that open/close many sessions.
            try { _library.UnregisterSession(this); } catch { /* tracker may already be torn down */ }
        }
    }
}
