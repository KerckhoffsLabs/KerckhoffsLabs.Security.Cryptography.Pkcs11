using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// Base class for the strongly-typed PKCS#11 mechanism parameters — the public surface over
/// the raw <c>CK_*_PARAMS</c> interop structs. Instances are passed to <c>Mechanism</c>
/// constructors and the message-based crypto methods (e.g.
/// <c>new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(...))</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Ownership:</b> passing an instance to a <c>Mechanism</c> constructor transfers ownership —
/// disposing that mechanism disposes this object too. Disposal is idempotent, so disposing it
/// yourself as well is harmless; sharing one instance across two mechanisms is not, because the
/// first mechanism disposed frees the buffers the second still points at. Construct one parameter
/// object per mechanism.
/// </para>
/// The marshalling contract (<see cref="ToMarshalableStructure"/>) is <c>internal</c>: callers
/// select from the library-provided <c>Ckm*Params</c> types and cannot define their own through
/// this path, which guarantees only blittable <c>[PackedForPkcs11]</c> structs ever reach
/// unmanaged memory. For raw or vendor-specific parameter blocks, use the
/// <c>Mechanism(type, byte[])</c> constructor instead.
/// </remarks>
public abstract class MechanismParameters : IDisposable
{
    /// <summary>
    /// Returns the <c>[PackedForPkcs11]</c>-marked interop struct that the library marshals to
    /// unmanaged memory. Internal: the concrete struct type is not part of the public API.
    /// </summary>
    internal abstract object ToMarshalableStructure();

    /// <summary>
    /// Builds the <c>[PackedForPkcs11]</c> interop struct, allocating any buffers its pointer fields
    /// need inside <paramref name="scope"/>.
    /// </summary>
    /// <remarks>
    /// The scope outlives this call and is released by the session once the native call returns, so
    /// implementations own nothing and need no disposal of their own.
    /// </remarks>
    internal virtual object BuildMarshalable(MechanismParameterScope scope) => ToMarshalableStructure();

    /// <summary>
    /// Copies anything the token wrote into <paramref name="marshalled"/> back into managed state,
    /// while the scope that owns it is still alive. The default does nothing; only the parameter
    /// types with output fields override it.
    /// </summary>
    internal virtual void AbsorbOutput(object marshalled) { }

    /// <summary>0 until some <c>Mechanism</c> has claimed this instance, 1 afterwards.</summary>
    private int _owned;

    /// <summary>
    /// Claims this instance for a single <c>Mechanism</c>, returning <see langword="false"/> if
    /// another one already owns it.
    /// </summary>
    /// <remarks>
    /// Each mechanism marshals its own copy of the parameter struct, pointer fields included, so two
    /// mechanisms sharing one instance would hold independent copies of the same buffer addresses.
    /// Disposing either mechanism frees those buffers and leaves the other pointing at released
    /// memory — which the token would then read. Claiming makes that a loud failure at construction
    /// rather than a silent one at the boundary.
    /// </remarks>
    internal bool TryClaimOwnership() => Interlocked.Exchange(ref _owned, 1) == 0;

    /// <summary>
    /// Releases the unmanaged parameter buffers held by this instance, then suppresses finalization.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the unmanaged parameter buffers. <paramref name="disposing"/> is <see langword="true"/>
    /// when called from <see cref="Dispose()"/> and <see langword="false"/> from a finalizer; the
    /// concrete parameter types own only unmanaged memory, so they free it on both paths.
    /// </summary>
    /// <param name="disposing"><see langword="true"/> if called deterministically from <see cref="Dispose()"/>.</param>
    protected abstract void Dispose(bool disposing);
}
