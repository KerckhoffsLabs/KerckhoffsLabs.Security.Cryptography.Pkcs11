using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_SALSA20_PARAMS"/>. Used with the raw CKM_SALSA20 stream cipher mechanism (PKCS#11 v3.0).
/// </summary>
public sealed class CkmSalsa20Params : MechanismParameters
{
    private readonly byte[] _blockCounterBytes;
    private readonly byte[] _nonceBytes;
    private readonly int _nonceBits;

    /// <summary>
    /// Initializes Salsa20 raw-mode parameters.
    /// </summary>
    /// <param name="blockCounter">Initial block counter (8 bytes).</param>
    /// <param name="nonce">Nonce bytes (typically 8).</param>
    /// <param name="nonceBits">Nonce length in bits (typically 64).</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="blockCounter"/> or <paramref name="nonce"/> is empty.</exception>
    public CkmSalsa20Params(ReadOnlySpan<byte> blockCounter, ReadOnlySpan<byte> nonce, int nonceBits)
    {
        if (blockCounter.IsEmpty) throw new ArgumentException("Block counter must not be empty.", nameof(blockCounter));
        if (nonce.IsEmpty) throw new ArgumentException("Nonce must not be empty.", nameof(nonce));

        _blockCounterBytes = blockCounter.ToArray();
        _nonceBytes = nonce.ToArray();
        _nonceBits = nonceBits;
    }

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_SALSA20_PARAMS
        {
            BlockCounter = scope.Write(_blockCounterBytes),
            Nonce = scope.Write(_nonceBytes),
            NonceBits = (NativeCULong)_nonceBits,
        };
    }
}
