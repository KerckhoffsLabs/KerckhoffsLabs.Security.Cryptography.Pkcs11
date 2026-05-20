using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_SP800_108_FEEDBACK_KDF_PARAMS"/>. Used
/// with CKM_SP800_108_FEEDBACK_KDF (PKCS#11 v3.0). Same caller-owns-buffer contract
/// as <see cref="CkmSp800108KdfParams"/>, plus an IV that this wrapper copies into a
/// freshly-allocated unmanaged buffer
/// </summary>
public sealed class CkmSp800108FeedbackKdfParams : IMechanismParams
{
    private CK_SP800_108_FEEDBACK_KDF_PARAMS _lowLevelParams;
    private IntPtr _iv;
    private bool _disposed;

    /// <summary>
    /// Initializes SP800-108 feedback-KDF parameters.
    /// </summary>
    /// <param name="prfType">PRF mechanism.</param>
    /// <param name="dataParams">Pointer to a pinned array of <see cref="CK_PRF_DATA_PARAM"/>.</param>
    /// <param name="numberOfDataParams">Number of entries in <paramref name="dataParams"/>.</param>
    /// <param name="iv">Feedback-chain IV bytes (this wrapper copies them).</param>
    /// <param name="additionalDerivedKeys">Optional pinned array of <see cref="CK_DERIVED_KEY"/>.</param>
    /// <param name="additionalDerivedKeysCount">Number of entries in <paramref name="additionalDerivedKeys"/>.</param>
    public CkmSp800108FeedbackKdfParams(CKM prfType, IntPtr dataParams, ulong numberOfDataParams, ReadOnlySpan<byte> iv, IntPtr additionalDerivedKeys = default, ulong additionalDerivedKeysCount = 0)
    {
        if (!iv.IsEmpty)
        {
            _iv = UnmanagedMemory.Allocate(iv.Length);
            UnmanagedMemory.Write(_iv, iv);
        }

        _lowLevelParams = new()
        {
            PrfType = (NativeCULong)(ulong)prfType,
            NumberOfDataParams = (NativeCULong)numberOfDataParams,
            DataParams = dataParams,
            IVLen = (NativeCULong)iv.Length,
            IV = _iv,
            AdditionalDerivedKeys = (NativeCULong)additionalDerivedKeysCount,
            AdditionalDerivedKeysPtr = additionalDerivedKeys,
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
        UnmanagedMemory.Free(ref _iv);
        _lowLevelParams.IV = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmSp800108FeedbackKdfParams() => Dispose();
}
