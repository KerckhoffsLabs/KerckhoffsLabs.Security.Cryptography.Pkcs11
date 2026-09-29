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
/// so nothing needs releasing and sharing one instance across two mechanisms is safe — each
/// marshals into its own scope.
/// </para>
/// The marshalling contract (<see cref="BuildMarshalable"/>) is <c>internal</c>: callers select from
/// the library-provided <c>Ckm*Params</c> types and cannot define their own through this path, which
/// guarantees only blittable <c>[PackedForPkcs11]</c> structs ever reach unmanaged memory. For raw or
/// vendor-specific parameter blocks, use the <c>Mechanism(type, byte[])</c> constructor instead.
/// </remarks>
public abstract class MechanismParameters
{
    /// <summary>
    /// Builds the <c>[PackedForPkcs11]</c> interop struct, allocating any buffers its pointer fields
    /// need inside <paramref name="scope"/>. Internal: the concrete struct type is not part of the
    /// public API.
    /// </summary>
    /// <remarks>
    /// The scope outlives this call and is released by the session once the native call returns, so
    /// implementations own nothing.
    /// </remarks>
    internal abstract object BuildMarshalable(MechanismParameterScope scope);

    /// <summary>
    /// Copies anything the token wrote into <paramref name="marshalled"/> back into managed state,
    /// while the scope that owns it is still alive. The default does nothing; only the parameter
    /// types with output fields override it.
    /// </summary>
    internal virtual void AbsorbOutput(object marshalled) { }

    /// <summary>
    /// Whether the token writes into this descriptor's block and <see cref="AbsorbOutput"/> copies the
    /// result back into managed state. <see langword="false"/> for input-only parameters.
    /// </summary>
    /// <remarks>
    /// Sharing one descriptor across mechanisms is safe in general — each marshals into its own block.
    /// It stops being safe when the descriptor carries output and drives both halves of a
    /// dual-mechanism operation, because both halves absorb into the same managed buffer and the first
    /// result is lost. The session rejects that pairing, and this is how it recognises it.
    /// </remarks>
    internal virtual bool AbsorbsTokenOutput => false;
}
