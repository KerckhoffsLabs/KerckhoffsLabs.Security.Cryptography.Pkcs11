using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Internal helper that synthesizes a managed public-key view from attributes on a
/// PKCS#11 private-key object when no <c>CKO_PUBLIC_KEY</c> companion is stored on the
/// token. Used by <see cref="Pkcs11Key"/> to support verify-only / encrypt-only paths
/// that need only public material.
/// </summary>
internal static class Pkcs11PublicKeyView
{
    /// <summary>
    /// Reads CKA_MODULUS + CKA_PUBLIC_EXPONENT from the private-key object identified by
    /// <paramref name="privateHandle"/> and returns the corresponding
    /// <see cref="RSAParameters"/>. Returns <c>null</c> if either attribute is missing
    /// or marked sensitive.
    /// </summary>
    public static RSAParameters? TrySynthesizeRsa(Pkcs11Session session, ObjectHandle privateHandle)
    {
        var attrs = session.GetAttributeValue(privateHandle, new List<CKA>
        {
            CKA.CKA_MODULUS,
            CKA.CKA_PUBLIC_EXPONENT,
        });

        try
        {
            if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
                return null;

            return new RSAParameters
            {
                Modulus = attrs[0].GetValueAsByteArray(),
                Exponent = attrs[1].GetValueAsByteArray(),
            };
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }

    /// <summary>
    /// Reads CKA_EC_POINT + CKA_EC_PARAMS from a CKO_PRIVATE_KEY object and returns the
    /// corresponding <see cref="ECParameters"/>. Returns <c>null</c> if either attribute
    /// is unreadable (per PKCS#11 v3.1, CKA_EC_POINT is optional on private-key
    /// objects).
    /// </summary>
    public static ECParameters? TrySynthesizeEc(Pkcs11Session session, ObjectHandle privateHandle)
    {
        var attrs = session.GetAttributeValue(privateHandle, new List<CKA>
        {
            CKA.CKA_EC_POINT,
            CKA.CKA_EC_PARAMS,
        });

        try
        {
            if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
                return null;

            // CKA_EC_POINT is DER-encoded OCTET STRING wrapping the uncompressed point.
            byte[] der = attrs[0].GetValueAsByteArray();
            ReadOnlySpan<byte> pointBytes = StripDerOctetString(der);
            if (pointBytes.IsEmpty) return null;

            // Point format: 0x04 || X || Y for uncompressed.
            if (pointBytes[0] != 0x04) return null;
            int coordLen = (pointBytes.Length - 1) / 2;
            if (coordLen <= 0 || pointBytes.Length != 1 + 2 * coordLen) return null;

            byte[] x = pointBytes.Slice(1, coordLen).ToArray();
            byte[] y = pointBytes.Slice(1 + coordLen, coordLen).ToArray();

            byte[] paramsBytes = attrs[1].GetValueAsByteArray();
            ECCurve curve = ResolveNamedCurve(paramsBytes);

            return new ECParameters
            {
                Curve = curve,
                Q = new ECPoint { X = x, Y = y },
            };
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
    }

    private static ReadOnlySpan<byte> StripDerOctetString(byte[] der)
    {
        if (der.Length < 2 || der[0] != 0x04) return ReadOnlySpan<byte>.Empty;

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
            return ReadOnlySpan<byte>.Empty;
        }

        if (offset + len > der.Length) return ReadOnlySpan<byte>.Empty;
        return der.AsSpan(offset, len);
    }

    private static ECCurve ResolveNamedCurve(byte[] derOid)
    {
        // OID 1.2.840.10045.3.1.7 = secp256r1 (P-256)
        // OID 1.3.132.0.34       = secp384r1 (P-384)
        // OID 1.3.132.0.35       = secp521r1 (P-521)
        ReadOnlySpan<byte> p256 = new byte[]
            { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
        ReadOnlySpan<byte> p384 = new byte[]
            { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
        ReadOnlySpan<byte> p521 = new byte[]
            { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };

        if (derOid.AsSpan().SequenceEqual(p256))
            return ECCurve.CreateFromFriendlyName("nistP256");
        if (derOid.AsSpan().SequenceEqual(p384))
            return ECCurve.CreateFromFriendlyName("nistP384");
        if (derOid.AsSpan().SequenceEqual(p521))
            return ECCurve.CreateFromFriendlyName("nistP521");

        return default;
    }
}
