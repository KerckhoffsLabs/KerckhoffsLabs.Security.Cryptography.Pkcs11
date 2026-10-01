namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// The RFC 3610 limits shared by <see cref="CkmAesCcmParams"/> and <see cref="CkmCcmMessageParams"/>,
/// checked before a malformed <c>CK_CCM_PARAMS</c> or <c>CK_CCM_MESSAGE_PARAMS</c> reaches the token,
/// where it would surface as an opaque vendor error instead of an argument exception.
/// </summary>
internal static class CcmLimits
{
    /// <summary>
    /// Checks that <paramref name="nonce"/> is 7 to 13 bytes and that <paramref name="dataLen"/> fits the
    /// length field it leaves: CCM encodes the message length in <c>L = 15 − nonce length</c> bytes, so
    /// the length must be below <c>2^(8L)</c> (RFC 3610 §2.1). Only 13- and 12-byte nonces can be
    /// exceeded by an <see cref="int"/>: below 65,536 and 16,777,216 bytes respectively.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="dataLen"/> is negative or
    /// does not fit the length field.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="nonce"/> is not 7 to 13 bytes long.</exception>
    public static void ValidateNonceAndDataLength(int dataLen, ReadOnlySpan<byte> nonce)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(dataLen);
        if (nonce.Length is < 7 or > 13)
            throw new ArgumentException("CCM nonce must be 7..13 bytes (RFC 3610).", nameof(nonce));

        int lengthFieldBits = 8 * (15 - nonce.Length);
        if (lengthFieldBits < 31 && dataLen >= 1 << lengthFieldBits)
            throw new ArgumentOutOfRangeException(nameof(dataLen), dataLen,
                $"A {nonce.Length}-byte CCM nonce leaves a {15 - nonce.Length}-byte length field, so the data must be shorter than {1 << lengthFieldBits} bytes (RFC 3610).");
    }
}
