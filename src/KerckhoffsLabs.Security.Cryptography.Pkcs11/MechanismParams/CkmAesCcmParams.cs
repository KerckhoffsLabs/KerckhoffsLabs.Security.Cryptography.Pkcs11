using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_CCM_PARAMS"/>. A managed descriptor: it holds the nonce and
/// AAD as managed arrays and is rebuilt into each call's own scope, so one instance may safely back
/// several mechanisms.
/// </summary>
public sealed class CkmAesCcmParams : MechanismParameters
{
    private readonly byte[] _nonceBytes;
    private readonly byte[] _aadBytes;
    private readonly int _dataLen;
    private readonly int _macLen;

    /// <summary>
    /// Initializes the CCM parameters.
    /// </summary>
    /// <param name="dataLen">Length of the plaintext (CCM requires it known up-front). It must fit the
    /// length field the nonce leaves: below 65,536 bytes with a 13-byte nonce, 16,777,216 with a 12-byte one.</param>
    /// <param name="nonce">Nonce, 7 to 13 bytes (RFC 3610).</param>
    /// <param name="aad">Additional authenticated data; pass <c>default</c> for none.</param>
    /// <param name="macLen">MAC (tag) length in bytes; must be one of {4, 6, 8, 10, 12, 14, 16}.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="nonce"/> is not 7 to 13 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="dataLen"/> is negative or too long for the nonce's length field, or <paramref name="macLen"/> is not one of {4, 6, 8, 10, 12, 14, 16}.</exception>
    public CkmAesCcmParams(int dataLen, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, int macLen)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(dataLen);
        if (nonce.Length is < 7 or > 13)
            throw new ArgumentException("CCM nonce must be 7..13 bytes (RFC 3610).", nameof(nonce));
        // RFC 3610 §2.1 encodes the data length in L = 15 - nonce length bytes, so it must be below
        // 2^(8L). With an int length, only 13- and 12-byte nonces leave a field it can overflow.
        int lengthFieldBits = 8 * (15 - nonce.Length);
        if (lengthFieldBits < 31 && dataLen >= 1 << lengthFieldBits)
            throw new ArgumentOutOfRangeException(nameof(dataLen), dataLen,
                $"A {nonce.Length}-byte CCM nonce leaves a {15 - nonce.Length}-byte length field, so the data must be shorter than {1 << lengthFieldBits} bytes (RFC 3610).");
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
}
