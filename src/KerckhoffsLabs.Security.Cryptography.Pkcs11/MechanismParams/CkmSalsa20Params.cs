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
    /// <param name="blockCounter">Initial block counter — must be exactly 8 bytes; <c>CK_SALSA20_PARAMS</c>
    /// carries no length field for it, so the module always reads 8 bytes from the pointer.</param>
    /// <param name="nonce">Nonce bytes (8, matching <paramref name="nonceBits"/>).</param>
    /// <param name="nonceBits">Nonce length in bits. CKM_SALSA20 defines only 64.</param>
    /// <exception cref="ArgumentException">
    /// Thrown if <paramref name="nonce"/> is empty, or if <paramref name="blockCounter"/> is not exactly 8
    /// bytes long — the module reads 8 bytes from the pointer regardless of the buffer's actual size, so a
    /// shorter buffer here is an out-of-bounds read on the token.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown if <paramref name="nonceBits"/> is not 64, or exceeds the byte length of <paramref name="nonce"/> —
    /// the module reads <c>nonceBits / 8</c> bytes from the pointer regardless of the buffer's actual size.
    /// </exception>
    public CkmSalsa20Params(ReadOnlySpan<byte> blockCounter, ReadOnlySpan<byte> nonce, int nonceBits)
    {
        if (blockCounter.Length != 8)
            throw new ArgumentException("Block counter must be exactly 8 bytes (CK_SALSA20_PARAMS has no length field for it).", nameof(blockCounter));
        if (nonce.IsEmpty) throw new ArgumentException("Nonce must not be empty.", nameof(nonce));
        if (nonceBits != 64)
            throw new ArgumentOutOfRangeException(nameof(nonceBits), nonceBits, "CKM_SALSA20 defines the nonce width as 64 bits.");
        if (nonceBits / 8 > nonce.Length)
            throw new ArgumentOutOfRangeException(nameof(nonceBits), nonceBits,
                $"Exceeds the nonce buffer's length ({nonce.Length} bytes).");

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
