using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_XEDDSA_PARAMS"/>. Used with CKM_XEDDSA (Signal-protocol XEdDSA signing, PKCS#11 v3.0).
/// </summary>
public sealed class CkmXeddsaParams : IMechanismParams
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
    public object ToMarshalableStructure()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;


        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmXeddsaParams() => Dispose();
}
