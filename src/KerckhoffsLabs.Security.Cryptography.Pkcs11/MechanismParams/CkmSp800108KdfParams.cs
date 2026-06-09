using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_SP800_108_KDF_PARAMS"/>. Used with
/// CKM_SP800_108_COUNTER_KDF and CKM_SP800_108_DOUBLE_PIPELINE_KDF (PKCS#11 v3.0).
/// The data-params array is owned by the caller and must remain pinned for the
/// lifetime of this instance — typically built from a list of <see cref="CK_PRF_DATA_PARAM"/>
/// entries that themselves point into other unmanaged buffers. The additional-derived-keys
/// array is optional
/// </summary>
public sealed class CkmSp800108KdfParams : MechanismParameters
{
    private CK_SP800_108_KDF_PARAMS _lowLevelParams;

    private bool _disposed;

    /// <summary>
    /// Initializes SP800-108 KDF parameters with a pre-built data-params block.
    /// </summary>
    /// <param name="prfType">PRF mechanism (a CKM_*_HMAC variant or CKM_AES_CMAC).</param>
    /// <param name="dataParams">Pointer to a pinned array of <see cref="CK_PRF_DATA_PARAM"/>.</param>
    /// <param name="numberOfDataParams">Number of entries in <paramref name="dataParams"/>.</param>
    /// <param name="additionalDerivedKeys">Optional pinned array of <see cref="CK_DERIVED_KEY"/> for sibling keys.</param>
    /// <param name="additionalDerivedKeysCount">Number of entries in <paramref name="additionalDerivedKeys"/>.</param>
    public CkmSp800108KdfParams(CKM prfType, IntPtr dataParams, ulong numberOfDataParams, IntPtr additionalDerivedKeys = default, ulong additionalDerivedKeysCount = 0)
    {
        _lowLevelParams = new()
        {
            PrfType = (NativeCULong)(ulong)prfType,
            NumberOfDataParams = (NativeCULong)numberOfDataParams,
            DataParams = dataParams,
            AdditionalDerivedKeys = (NativeCULong)additionalDerivedKeysCount,
            AdditionalDerivedKeysPtr = additionalDerivedKeys,
        };
    }

    /// <inheritdoc/>
    internal override object ToMarshalableStructure()
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

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmSp800108KdfParams() => Dispose(false);
}
