using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_RSA_PKCS_OAEP_PARAMS"/>. A managed descriptor: it holds the
/// optional source data as a managed array and is rebuilt into each call's own scope, so disposal
/// order relative to the <see cref="Mechanism"/> does not matter and one instance may back several
/// mechanisms.
/// </summary>
public sealed class CkmRsaPkcsOaepParams : MechanismParameters
{
    private readonly byte[] _sourceDataBytes;
    private readonly CKM _hashAlg;
    private readonly CKG _mgf;
    private bool _disposed;

    /// <summary>
    /// Initializes OAEP parameters. Defaults to <c>CKZ_DATA_SPECIFIED</c> with empty source.
    /// </summary>
    /// <param name="hashAlg">Hash mechanism (typically <see cref="CKM.CKM_SHA256"/>).</param>
    /// <param name="mgf">Mask generation function (typically <see cref="CKG.CKG_MGF1_SHA256"/>).</param>
    /// <param name="sourceData">Optional encoding-parameter source data; pass <c>default</c> for none.</param>
    public CkmRsaPkcsOaepParams(CKM hashAlg, CKG mgf, ReadOnlySpan<byte> sourceData = default)
    {
        _sourceDataBytes = sourceData.ToArray();
        _hashAlg = hashAlg;
        _mgf = mgf;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new CK_RSA_PKCS_OAEP_PARAMS
        {
            HashAlg = _hashAlg.ToCULong(),
            Mgf = _mgf.ToCULong(),
            Source = CKZ.CKZ_DATA_SPECIFIED,
            SourceData = scope.Write(_sourceDataBytes),
            SourceDataLen = (NativeCULong)_sourceDataBytes.Length,
        };
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
    }

    /// <summary>Hash algorithm used in the OAEP encoding.</summary>
    public CKM HashAlg => _hashAlg;

    /// <summary>Mask generation function.</summary>
    public CKG Mgf => _mgf;
}
