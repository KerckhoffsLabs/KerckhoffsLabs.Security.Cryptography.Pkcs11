using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_XEDDSA_PARAMS"/>. Used with CKM_XEDDSA (Signal-protocol XEdDSA signing, PKCS#11 v3.0).
/// </summary>
public sealed class CkmXeddsaParams : MechanismParameters
{
    private readonly CKM _hashType;

    /// <summary>
    /// Initializes XEdDSA parameters.
    /// </summary>
    /// <param name="hashType">
    /// Hash mechanism (CK_XEDDSA_HASH_TYPE). The spec typedefs this as a bare <c>CK_ULONG</c> with
    /// no constants of its own, reusing the mechanism-type namespace (e.g. <see cref="CKM.CKM_SHA512"/>).
    /// </param>
    public CkmXeddsaParams(CKM hashType) => _hashType = hashType;

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
        => new CK_XEDDSA_PARAMS { Hash = (NativeCULong)(ulong)_hashType };
}
