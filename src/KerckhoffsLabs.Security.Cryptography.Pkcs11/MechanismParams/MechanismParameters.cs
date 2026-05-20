namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// Base class for the strongly-typed PKCS#11 mechanism parameters — the public surface over
/// the raw <c>CK_*_PARAMS</c> interop structs. Instances are passed to <c>Mechanism</c>
/// constructors and the message-based crypto methods (e.g.
/// <c>new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(...))</c>).
/// </summary>
/// <remarks>
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

    /// <inheritdoc/>
    public abstract void Dispose();
}
