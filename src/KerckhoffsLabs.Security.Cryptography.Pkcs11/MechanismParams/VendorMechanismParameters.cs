using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// Base class for parameters of a vendor-defined mechanism this library does not model — the
/// <c>CKM_VENDOR_DEFINED</c> range, such as opencryptoki's IBM mechanisms or an HSM's proprietary
/// extensions.
/// </summary>
/// <remarks>
/// <para>
/// Derive from this, describe the vendor's <c>CK_*_PARAMS</c> fields in declaration order, and pass
/// the instance to a <see cref="Mechanism"/> exactly like a built-in parameter type:
/// </para>
/// <code>
/// public sealed class IbmExampleParams(ulong mode, byte[] nonce) : VendorMechanismParameters
/// {
///     protected override void Describe(Pkcs11ParameterWriter writer) =&gt; writer
///         .CkULong(mode)
///         .Buffer(nonce)
///         .CkULong((ulong)nonce.Length);
/// }
///
/// var mech = new Mechanism(0x80010036UL, new IbmExampleParams(mode, nonce));
/// byte[] signature = key.Sign(mech, data);
/// </code>
/// <para>
/// The field list is all you supply: offsets, padding, <c>CK_ULONG</c> width and pointer size are the
/// library's job, because they differ by platform and getting them wrong corrupts the block silently
/// rather than failing. Instances hold managed data only — there is nothing to dispose, and one
/// instance may back several mechanisms.
/// </para>
/// <para>
/// For a mechanism whose parameter is an opaque blob rather than a struct, use the
/// <c>Mechanism(type, byte[])</c> constructor instead. Parameters the token writes back into are not
/// supported through this path.
/// </para>
/// </remarks>
public abstract class VendorMechanismParameters : MechanismParameters
{
    /// <summary>
    /// Appends the vendor struct's fields to <paramref name="writer"/>, in the order the vendor's
    /// header declares them.
    /// </summary>
    /// <param name="writer">Collects the fields; see <see cref="Pkcs11ParameterWriter"/>.</param>
    protected abstract void Describe(Pkcs11ParameterWriter writer);

    internal sealed override object BuildMarshalable(MechanismParameterScope scope)
    {
        var writer = new Pkcs11ParameterWriter(scope);
        Describe(writer);
        return writer.Build();
    }
}
