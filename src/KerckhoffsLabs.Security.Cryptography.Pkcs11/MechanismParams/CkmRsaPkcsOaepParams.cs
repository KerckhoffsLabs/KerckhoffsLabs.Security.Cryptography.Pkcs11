using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_RSA_PKCS_OAEP_PARAMS"/>. Owns the unmanaged
/// buffer for the optional source data. Dispose this instance AFTER the
/// <see cref="Mechanism"/> that holds a reference to it has been disposed.
/// </summary>
public sealed class CkmRsaPkcsOaepParams : IMechanismParams
{
    private CK_RSA_PKCS_OAEP_PARAMS _lowLevelParams;
    private IntPtr _sourceData;
    private bool _disposed;

    /// <summary>
    /// Initializes OAEP parameters. Defaults to <c>CKZ_DATA_SPECIFIED</c> with empty source.
    /// </summary>
    /// <param name="hashAlg">Hash mechanism (typically <see cref="CKM.CKM_SHA256"/>).</param>
    /// <param name="mgf">Mask generation function (typically <see cref="CKG.CKG_MGF1_SHA256"/>).</param>
    /// <param name="sourceData">Optional encoding-parameter source data; pass <c>default</c> for none.</param>
    public CkmRsaPkcsOaepParams(CKM hashAlg, CKG mgf, ReadOnlySpan<byte> sourceData = default)
    {
        if (!sourceData.IsEmpty)
        {
            _sourceData = UnmanagedMemory.Allocate(sourceData.Length);
            UnmanagedMemory.Write(_sourceData, sourceData);
        }

        _lowLevelParams = new()
        {
            HashAlg = hashAlg.ToCULong(),
            Mgf = mgf.ToCULong(),
            Source = CKZ.CKZ_DATA_SPECIFIED,
            SourceData = _sourceData,
            SourceDataLen = (NativeCULong)sourceData.Length,
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
        UnmanagedMemory.Free(ref _sourceData);
        _lowLevelParams.SourceData = IntPtr.Zero;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Hash algorithm used in the OAEP encoding.</summary>
    public CKM HashAlg => _lowLevelParams.HashAlg.ToCKM();

    /// <summary>Mask generation function.</summary>
    public CKG Mgf => _lowLevelParams.Mgf.ToCKG();

    /// <summary>Finalizer to release unmanaged memory if Dispose was not called.</summary>
    ~CkmRsaPkcsOaepParams() => Dispose();
}
