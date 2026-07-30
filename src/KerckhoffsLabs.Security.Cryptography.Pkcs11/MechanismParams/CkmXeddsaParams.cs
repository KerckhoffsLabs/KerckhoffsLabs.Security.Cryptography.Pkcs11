using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_XEDDSA_PARAMS"/>. Used with CKM_XEDDSA (Signal-protocol XEdDSA signing, PKCS#11 v3.0).
/// </summary>
public sealed class CkmXeddsaParams : MechanismParameters
{
    private readonly ulong _hashType;
    private bool _disposed;

    /// <summary>
    /// Initializes XEdDSA parameters.
    /// </summary>
    /// <param name="hashType">Hash function (CK_XEDDSA_HASH_TYPE).</param>
    public CkmXeddsaParams(ulong hashType) => _hashType = hashType;

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new CK_XEDDSA_PARAMS { Hash = (NativeCULong)_hashType };
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
    }
}
