using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;

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
/// <c>C_CloseSession</c> has run. It is taken whatever implementation sits behind
/// <see cref="ILowLevelPkcs11Library"/>: a test double gets a detached module handle.
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

    /// <summary>Creates a session handle. The handle is invalid if <paramref name="sessionId"/> is <see cref="CK.CK_INVALID_HANDLE"/>.</summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="library"/> is null.</exception>
    public Pkcs11SessionHandle(ILowLevelPkcs11Library library, NativeCULong sessionId)
        : base(IntPtr.Zero, ownsHandle: true)
    {
        ArgumentNullException.ThrowIfNull(library);
        _module = library.Module;
        _sessionId = sessionId;

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
            // Release last: only after C_CloseSession has had its chance to run does the module
            // become eligible for its own SafeHandle release.
            if (_moduleRefAdded) _module.ReleaseUse();
        }
    }
}
