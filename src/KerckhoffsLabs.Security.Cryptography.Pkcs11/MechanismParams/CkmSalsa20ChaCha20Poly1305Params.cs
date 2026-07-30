using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_SALSA20_CHACHA20_POLY1305_PARAMS"/>. A managed descriptor:
/// it holds the nonce and AAD as managed arrays and is rebuilt into each call's own scope, so
/// disposal order relative to the <see cref="Mechanism"/> does not matter and one instance may back
/// several mechanisms.
/// </summary>
public sealed class CkmSalsa20ChaCha20Poly1305Params : MechanismParameters
{
    private readonly byte[] _nonceBytes;
    private readonly byte[] _aadBytes;
    private bool _disposed;

    /// <summary>
    /// Initializes the ChaCha20-Poly1305 / Salsa20-Poly1305 parameters.
    /// </summary>
    /// <param name="nonce">Nonce (typically 12 bytes / 96 bits for ChaCha20-Poly1305).</param>
    /// <param name="aad">Additional authenticated data; pass <c>default</c> for none.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="nonce"/> is empty.</exception>
    public CkmSalsa20ChaCha20Poly1305Params(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad)
    {
        if (nonce.IsEmpty) throw new ArgumentException("Nonce must not be empty.", nameof(nonce));

        _nonceBytes = nonce.ToArray();
        _aadBytes = aad.IsEmpty ? [] : aad.ToArray();
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new CK_SALSA20_CHACHA20_POLY1305_PARAMS
        {
            Nonce = scope.Write(_nonceBytes),
            NonceLen = (NativeCULong)_nonceBytes.Length,
            AAD = scope.Write(_aadBytes),
            AADLen = (NativeCULong)_aadBytes.Length,
        };
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
    }
}
