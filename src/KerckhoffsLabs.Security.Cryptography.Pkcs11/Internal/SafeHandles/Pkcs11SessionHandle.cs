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
/// Mere GC reachability does not order this: <see cref="SafeHandle"/> is a
/// <c>CriticalFinalizerObject</c>, and the CLR gives no relative ordering guarantee between two
/// independent critical finalizers — a strong reference to the library only stops it from being
/// *collected*, not from having its own module handle finalized (and the native module unmapped)
/// first if both this handle and the library become unreachable in the same GC. When the backing
/// library is a real, natively-loaded <see cref="LowLevelPkcs11Library"/>, this handle instead takes
/// an explicit <c>DangerousAddRef</c> on its <see cref="Pkcs11ModuleHandle"/> for its own lifetime and
/// releases it in <see cref="ReleaseHandle"/> — SafeHandle's own ref-counting is what actually defers
/// the module's release until this handle's <c>C_CloseSession</c> has run.
/// </remarks>
internal sealed class Pkcs11SessionHandle : SafeHandle
{
    private readonly ILowLevelPkcs11Library _library;

    /// <summary>
    /// The real library's module handle, ref-counted for this session's lifetime — <c>null</c> when
    /// <see cref="_library"/> is not a natively-loaded <see cref="LowLevelPkcs11Library"/> (a test
    /// double has no native module to protect).
    /// </summary>
    private readonly Pkcs11ModuleHandle? _moduleHandle;

    /// <summary>Whether <see cref="_moduleHandle"/>'s <c>DangerousAddRef</c> succeeded and must be released.</summary>
    private readonly bool _moduleHandleRefAdded;

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

        if (!IsInvalid && library is LowLevelPkcs11Library real)
        {
            _moduleHandle = real.ModuleHandle;
            _moduleHandle.DangerousAddRef(ref _moduleHandleRefAdded);
        }

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
        try
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
        finally
        {
            // Release last: only after C_CloseSession has had its chance to run does the module
            // become eligible for its own SafeHandle release.
            if (_moduleHandleRefAdded) _moduleHandle!.DangerousRelease();
        }
    }
}
