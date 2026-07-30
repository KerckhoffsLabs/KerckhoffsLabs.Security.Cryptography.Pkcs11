using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_CCM_PARAMS"/>. Owns the unmanaged buffers for
/// the nonce and AAD. Dispose AFTER the Mechanism holding it has been disposed.
/// </summary>
public sealed class CkmAesCcmParams : MechanismParameters
{
    private readonly byte[] _nonceBytes;
    private readonly byte[] _aadBytes;
    private readonly int _dataLen;
    private readonly int _macLen;
    private bool _disposed;

    /// <summary>
    /// Initializes the CCM parameters.
    /// </summary>
    /// <param name="dataLen">Length of the plaintext (CCM requires it known up-front).</param>
    /// <param name="nonce">Nonce (BCL: 7-13 bytes). Must not be empty.</param>
    /// <param name="aad">Additional authenticated data; pass <c>default</c> for none.</param>
    /// <param name="macLen">MAC (tag) length in bytes; must be one of {4, 6, 8, 10, 12, 14, 16}.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="nonce"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="dataLen"/> is negative, or <paramref name="macLen"/> is not one of {4, 6, 8, 10, 12, 14, 16}.</exception>
    public CkmAesCcmParams(int dataLen, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, int macLen)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(dataLen);
        if (nonce.IsEmpty) throw new ArgumentException("Nonce must not be empty.", nameof(nonce));
        if (macLen is not (4 or 6 or 8 or 10 or 12 or 14 or 16))
            throw new ArgumentOutOfRangeException(nameof(macLen),
                "CCM MAC length must be one of {4, 6, 8, 10, 12, 14, 16} bytes.");

        _nonceBytes = nonce.ToArray();
        _aadBytes = aad.IsEmpty ? [] : aad.ToArray();
        _dataLen = dataLen;
        _macLen = macLen;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new CK_CCM_PARAMS
        {
            DataLen = (NativeCULong)_dataLen,
            Nonce = scope.Write(_nonceBytes),
            NonceLen = (NativeCULong)_nonceBytes.Length,
            AAD = scope.Write(_aadBytes),
            AADLen = (NativeCULong)_aadBytes.Length,
            MACLen = (NativeCULong)_macLen,
        };
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
    }
}
