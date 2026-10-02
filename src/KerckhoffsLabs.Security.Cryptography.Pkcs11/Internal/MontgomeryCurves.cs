using System.Formats.Asn1;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The Montgomery curves of <c>CKK_EC_MONTGOMERY</c> keys (RFC 7748): X25519 and X448, whose public keys
/// and shared secrets are a single u-coordinate of 32 and 56 bytes.
/// </summary>
internal static class MontgomeryCurves
{
    /// <summary>
    /// The u-coordinate size of the curve <paramref name="ecParams"/> (<c>CKA_EC_PARAMS</c>) names, or
    /// <see langword="null"/> when it names neither X25519 nor X448. PKCS#11 v3.0 allows either form: the
    /// curve's OID (RFC 8410: 1.3.101.110 / 1.3.101.111) or its name as a PrintableString.
    /// </summary>
    internal static int? SizeOf(ReadOnlySpan<byte> ecParams)
    {
        try
        {
            var reader = new AsnReader(ecParams.ToArray(), AsnEncodingRules.DER);
            string name = reader.PeekTag().HasSameClassAndValue(Asn1Tag.ObjectIdentifier)
                ? reader.ReadObjectIdentifier()
                : reader.ReadCharacterString(UniversalTagNumber.PrintableString);
            return name switch
            {
                "1.3.101.110" or "curve25519" => 32,
                "1.3.101.111" or "curve448" => 56,
                _ => null,
            };
        }
        catch (Exception ex) when (ex is AsnContentException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// The raw peer u-coordinate of <paramref name="size"/> bytes in <paramref name="publicData"/>, given raw or
    /// wrapped in a DER OCTET STRING as some tokens return <c>CKA_EC_POINT</c>; <see langword="false"/> when it is
    /// neither. PKCS#11 requires a token to accept the raw form, and only allows the wrapped one.
    /// </summary>
    internal static bool TryGetUCoordinate(ReadOnlySpan<byte> publicData, int size, out ReadOnlySpan<byte> u)
    {
        if (publicData.Length == size)
        {
            u = publicData;
            return true;
        }
        if (publicData.Length == size + 2 && publicData[0] == 0x04 && publicData[1] == size)
        {
            u = publicData[2..];
            return true;
        }
        u = default;
        return false;
    }

    // The low-order u-coordinates (RFC 7748 §7), little-endian, including their non-canonical encodings p and
    // p + 1. Any of them gives a fixed shared secret whatever the private key. X25519 ignores bit 255, so its
    // entries are compared with that bit cleared.
    private static readonly byte[][] X25519LowOrder =
    [
        Convert.FromHexString("0000000000000000000000000000000000000000000000000000000000000000"),
        Convert.FromHexString("0100000000000000000000000000000000000000000000000000000000000000"),
        Convert.FromHexString("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        Convert.FromHexString("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        Convert.FromHexString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        Convert.FromHexString("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        Convert.FromHexString("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ];

    private static readonly byte[][] X448LowOrder =
    [
        Convert.FromHexString(new string('0', 112)),
        Convert.FromHexString("01" + new string('0', 110)),
        Convert.FromHexString("fe" + new string('f', 54) + "fe" + new string('f', 54)),
        Convert.FromHexString(new string('f', 56) + "fe" + new string('f', 54)),
        Convert.FromHexString(new string('0', 56) + new string('f', 56)),
    ];

    /// <summary>Whether <paramref name="u"/> is a low-order u-coordinate of the curve of that size.</summary>
    internal static bool IsLowOrder(ReadOnlySpan<byte> u, int size)
    {
        if (size == 32)
        {
            Span<byte> masked = stackalloc byte[32];
            u.CopyTo(masked);
            masked[31] &= 0x7F;
            foreach (byte[] point in X25519LowOrder)
                if (masked.SequenceEqual(point))
                    return true;
            return false;
        }
        foreach (byte[] point in X448LowOrder)
            if (u.SequenceEqual(point))
                return true;
        return false;
    }

    /// <summary>Whether <paramref name="secret"/> is all zeros, without branching on its bytes.</summary>
    internal static bool IsAllZero(ReadOnlySpan<byte> secret)
    {
        int accumulator = 0;
        foreach (byte b in secret)
            accumulator |= b;
        return accumulator == 0;
    }
}
