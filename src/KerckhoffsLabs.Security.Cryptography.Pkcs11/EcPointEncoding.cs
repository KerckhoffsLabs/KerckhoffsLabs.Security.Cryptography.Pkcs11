using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// The PKCS#11 encoding of an EC public key, both directions: <c>CKA_EC_POINT</c> is a DER OCTET STRING
/// wrapping the uncompressed point <c>0x04 ‖ X ‖ Y</c>, and <c>CKA_EC_PARAMS</c> is the DER-encoded
/// named-curve OID.
/// </summary>
internal static class EcPointEncoding
{
    /// <summary>
    /// Encodes an uncompressed EC point (0x04 ‖ X ‖ Y) as a DER OCTET STRING, the form PKCS#11 expects
    /// for <c>CKA_EC_POINT</c> and for the ECDH1 public-data parameter.
    /// </summary>
    internal static byte[] Encode(byte[] x, byte[] y)
    {
        byte[] raw = new byte[1 + x.Length + y.Length];
        raw[0] = 0x04;
        x.CopyTo(raw, 1);
        y.CopyTo(raw, 1 + x.Length);

        if (raw.Length < 0x80)
        {
            byte[] der = new byte[2 + raw.Length];
            der[0] = 0x04;
            der[1] = (byte)raw.Length;
            raw.CopyTo(der, 2);
            return der;
        }
        else
        {
            // Long-form length (one length byte covers all named curves up to 255-byte points).
            byte[] der = new byte[3 + raw.Length];
            der[0] = 0x04;
            der[1] = 0x81;
            der[2] = (byte)raw.Length;
            raw.CopyTo(der, 3);
            return der;
        }
    }

    /// <summary>
    /// The inverse of <see cref="Encode"/>: splits a <c>CKA_EC_POINT</c> value into its coordinates.
    /// Returns <see langword="false"/> when the bytes aren't a DER OCTET STRING wrapping an
    /// uncompressed point.
    /// </summary>
    internal static bool TryDecode(byte[] ecPoint, out byte[] x, out byte[] y)
    {
        x = y = [];

        ReadOnlySpan<byte> pointBytes = StripDerOctetString(ecPoint);
        if (pointBytes.IsEmpty) return false;

        // Point format: 0x04 || X || Y for uncompressed.
        if (pointBytes[0] != 0x04) return false;
        int coordLen = (pointBytes.Length - 1) / 2;
        if (coordLen <= 0 || pointBytes.Length != 1 + 2 * coordLen) return false;

        x = pointBytes.Slice(1, coordLen).ToArray();
        y = pointBytes.Slice(1 + coordLen, coordLen).ToArray();
        return true;
    }

    /// <summary>
    /// Parses raw <c>CKA_EC_POINT</c> + <c>CKA_EC_PARAMS</c> bytes into an <see cref="ECParameters"/>
    /// for a named curve (any curve in <see cref="Pkcs11ECCurve.NamedCurves"/>, and any other named-curve
    /// OID the host BCL recognises). Returns <see langword="null"/> when the inputs don't decode as a
    /// DER-OCTET-wrapped uncompressed point or <c>CKA_EC_PARAMS</c> isn't a DER-encoded curve OID.
    /// </summary>
    /// <param name="ecPoint">Raw <c>CKA_EC_POINT</c> bytes (DER OCTET STRING containing the uncompressed point).</param>
    /// <param name="ecParams">Raw <c>CKA_EC_PARAMS</c> bytes (DER-encoded named-curve OID).</param>
    internal static ECParameters? TryParsePublicKey(byte[] ecPoint, byte[] ecParams)
    {
        ArgumentNullException.ThrowIfNull(ecPoint);
        ArgumentNullException.ThrowIfNull(ecParams);

        if (!TryDecode(ecPoint, out byte[] x, out byte[] y)) return null;
        if (ResolveNamedCurve(ecParams) is not { } curve) return null;
        return new ECParameters { Curve = curve, Q = new ECPoint { X = x, Y = y } };
    }

    private static ReadOnlySpan<byte> StripDerOctetString(byte[] der)
    {
        if (der.Length < 2 || der[0] != 0x04) return [];

        int offset = 2;
        int len = der[1];
        if (len == 0x81 && der.Length >= 3)
        {
            len = der[2];
            offset = 3;
        }
        else if (len == 0x82 && der.Length >= 4)
        {
            len = (der[2] << 8) | der[3];
            offset = 4;
        }
        else if (len > 0x7F)
        {
            return [];
        }

        if (offset + len > der.Length) return [];
        return der.AsSpan(offset, len);
    }

    // CKA_EC_PARAMS for a named curve is the DER-encoded curve OID; bridge it to a BCL named curve
    // over that OID. Covers the whole Pkcs11ECCurve.NamedCurves catalog (NIST, secp256k1, Brainpool, SM2),
    // not just the NIST primes. Returns null when the bytes aren't a DER-encoded OID.
    private static ECCurve? ResolveNamedCurve(byte[] derOid)
    {
        try
        {
            return Pkcs11ECCurve.FromEcParams(derOid).ToECCurve();
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
