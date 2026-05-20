using KerckhoffsLabs.Runtime.InteropServices;
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
    private readonly ILowLevelPkcs11Library _library;

    /// <summary>Creates a session handle. The handle is invalid if <paramref name="sessionId"/> is <see cref="CK.CK_INVALID_HANDLE"/>.</summary>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="library"/> is null.</exception>
    public Pkcs11SessionHandle(ILowLevelPkcs11Library library, NativeCULong sessionId)
        : base(IntPtr.Zero, ownsHandle: true)
    {
        _library = library ?? throw new ArgumentNullException(nameof(library));
        SetHandle((IntPtr)(ulong)sessionId);
        // Register with the library so Pkcs11Library.Dispose can close us before C_Finalize
        // unloads the function table (BL-016).
        _library.RegisterSession(this);
    }

    /// <summary>The underlying PKCS#11 session handle.</summary>
    public NativeCULong SessionId => (NativeCULong)(ulong)handle;

    /// <inheritdoc/>
    public override bool IsInvalid => SessionId == CK.CK_INVALID_HANDLE;

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
