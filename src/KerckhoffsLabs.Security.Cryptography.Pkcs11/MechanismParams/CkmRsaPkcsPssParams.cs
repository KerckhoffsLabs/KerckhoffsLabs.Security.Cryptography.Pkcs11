using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_RSA_PKCS_PSS_PARAMS"/>. Owns no unmanaged
/// buffers — PSS params are three integers — but follows the IMechanismParams
/// contract so the secure helpers can construct a Mechanism uniformly.
/// </summary>
public sealed class CkmRsaPkcsPssParams : IMechanismParams
{
    private CK_RSA_PKCS_PSS_PARAMS _lowLevelParams;
    private bool _disposed;

    /// <summary>
    /// Initializes RSA-PSS parameters.
    /// </summary>
    /// <param name="hashAlg">Hash mechanism (typically <see cref="CKM.CKM_SHA256"/>).</param>
    /// <param name="mgf">Mask generation function (typically <see cref="CKG.CKG_MGF1_SHA256"/>).</param>
    /// <param name="saltLength">Salt length in bytes. RFC 8017 recommends matching the hash output length (32 for SHA-256).</param>
    public CkmRsaPkcsPssParams(CKM hashAlg, CKG mgf, int saltLength)
    {
        if (saltLength < 0)
            throw new ArgumentOutOfRangeException(nameof(saltLength), "Salt length must be non-negative.");

        _lowLevelParams = new CK_RSA_PKCS_PSS_PARAMS
        {
            HashAlg = hashAlg.ToCULong(),
            Mgf = mgf.ToCULong(),
            Len = (NativeCULong)saltLength,
        };
    }

    /// <inheritdoc/>
    public object ToMarshalableStructure()
    {
        if (_disposed) throw new ObjectDisposedException(GetType().FullName);
        return _lowLevelParams;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Hash algorithm used in the PSS encoding.</summary>
    public CKM HashAlg => _lowLevelParams.HashAlg.ToCKM();

    /// <summary>Mask generation function.</summary>
    public CKG Mgf => _lowLevelParams.Mgf.ToCKG();

    /// <summary>Salt length in bytes.</summary>
    public int SaltLength => (int)(ulong)_lowLevelParams.Len;

    /// <summary>No-op finalizer for symmetry with the other params wrappers; this type owns no unmanaged memory.</summary>
    ~CkmRsaPkcsPssParams() => Dispose();
}
