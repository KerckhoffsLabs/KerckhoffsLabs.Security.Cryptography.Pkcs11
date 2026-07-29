using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_RSA_PKCS_PSS_PARAMS"/>. Owns no unmanaged
/// buffers — PSS params are three integers — but follows the MechanismParams
/// contract so the secure helpers can construct a Mechanism uniformly.
/// </summary>
public sealed class CkmRsaPkcsPssParams : MechanismParameters
{
    private CK_RSA_PKCS_PSS_PARAMS _lowLevelParams;
    private bool _disposed;

    /// <summary>
    /// Initializes RSA-PSS parameters.
    /// </summary>
    /// <param name="hashAlg">Hash mechanism (typically <see cref="CKM.CKM_SHA256"/>).</param>
    /// <param name="mgf">Mask generation function (typically <see cref="CKG.CKG_MGF1_SHA256"/>).</param>
    /// <param name="saltLength">Salt length in bytes. RFC 8017 recommends matching the hash output length (32 for SHA-256).</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="saltLength"/> is negative.</exception>
    public CkmRsaPkcsPssParams(CKM hashAlg, CKG mgf, int saltLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(saltLength);

        _lowLevelParams = new()
        {
            HashAlg = hashAlg.ToCULong(),
            Mgf = mgf.ToCULong(),
            Len = (NativeCULong)saltLength,
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

    /// <summary>Hash algorithm used in the PSS encoding.</summary>
    public CKM HashAlg => _lowLevelParams.HashAlg.ToCKM();

    /// <summary>Mask generation function.</summary>
    public CKG Mgf => _lowLevelParams.Mgf.ToCKG();

    /// <summary>Salt length in bytes.</summary>
    public int SaltLength => (int)(ulong)_lowLevelParams.Len;

    // No finalizer: this type owns no unmanaged memory, so one would only put every instance on
    // the finalization queue and hold it an extra GC generation for a no-op. The sibling types
    // that allocate keep theirs; CkmRc2Params and CkmRc2CbcParams likewise have none.
}
