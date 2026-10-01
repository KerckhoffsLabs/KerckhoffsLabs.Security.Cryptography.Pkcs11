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
        CcmLimits.ValidateNonceAndDataLength(dataLen, nonce);
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
