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
/// Instances are pure managed descriptors: they hold the caller's values and build the interop
/// struct on demand into the per-call scope the session owns. Nothing unmanaged outlives the call,
/// so there is no disposal order to respect and sharing one instance across two mechanisms is safe —
/// each marshals into its own scope.
/// </para>
/// The marshalling contract (<see cref="BuildMarshalable"/>) is <c>internal</c>: callers select from
/// the library-provided <c>Ckm*Params</c> types and cannot define their own through this path, which
/// guarantees only blittable <c>[PackedForPkcs11]</c> structs ever reach unmanaged memory. For raw or
/// vendor-specific parameter blocks, use the <c>Mechanism(type, byte[])</c> constructor instead.
/// </remarks>
public abstract class MechanismParameters : IDisposable
{
    /// <summary>
    /// Builds the <c>[PackedForPkcs11]</c> interop struct, allocating any buffers its pointer fields
    /// need inside <paramref name="scope"/>. Internal: the concrete struct type is not part of the
    /// public API.
    /// </summary>
    /// <remarks>
    /// The scope outlives this call and is released by the session once the native call returns, so
    /// implementations own nothing and need no disposal of their own.
    /// </remarks>
    internal abstract object BuildMarshalable(MechanismParameterScope scope);

    /// <summary>
    /// Copies anything the token wrote into <paramref name="marshalled"/> back into managed state,
    /// while the scope that owns it is still alive. The default does nothing; only the parameter
    /// types with output fields override it.
    /// </summary>
    internal virtual void AbsorbOutput(object marshalled) { }

    // Nothing unmanaged is owned any more — the session's per-call scope holds it all. The
    // interface is retained for source compatibility and is removed in a separate change.

    /// <summary>
    /// Marks this instance disposed, after which <see cref="BuildMarshalable"/> throws. Idempotent.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Marks this instance disposed. Nothing unmanaged is released — there is none to release — so
    /// <paramref name="disposing"/> is not consulted.
    /// </summary>
    /// <param name="disposing"><see langword="true"/> if called deterministically from <see cref="Dispose()"/>.</param>
    protected abstract void Dispose(bool disposing);
}
