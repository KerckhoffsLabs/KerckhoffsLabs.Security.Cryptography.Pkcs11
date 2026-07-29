using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_XEDDSA_PARAMS"/>. Used with CKM_XEDDSA (Signal-protocol XEdDSA signing, PKCS#11 v3.0).
/// </summary>
public sealed class CkmXeddsaParams : MechanismParameters
{
    private CK_XEDDSA_PARAMS _lowLevelParams;

    private bool _disposed;

    /// <summary>
    /// Initializes XEdDSA parameters.
    /// </summary>
    /// <param name="hashType">Hash function (CK_XEDDSA_HASH_TYPE).</param>
    public CkmXeddsaParams(ulong hashType)
    {
        _lowLevelParams = new()
        {
            Hash = (NativeCULong)hashType,
        };
    }

    /// <inheritdoc/>
    internal override object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        _disposed = true;
    }

    // No finalizer: this type owns no unmanaged memory, so one would only put every instance on
    // the finalization queue and hold it an extra GC generation for a no-op. The sibling types
    // that allocate keep theirs; CkmRc2Params and CkmRc2CbcParams likewise have none.
}
