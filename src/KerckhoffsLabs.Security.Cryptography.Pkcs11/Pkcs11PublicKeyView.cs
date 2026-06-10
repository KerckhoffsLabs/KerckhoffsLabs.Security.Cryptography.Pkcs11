using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;
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
    internal static RSAParameters? TrySynthesizeRsa(Pkcs11Session session, ObjectHandle privateHandle)
    {
        var attrs = session.GetAttributeValue(privateHandle,
        [
            CKA.CKA_MODULUS,
            CKA.CKA_PUBLIC_EXPONENT,
        ]);

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
    /// Parses raw <c>CKA_EC_POINT</c> + <c>CKA_EC_PARAMS</c> bytes into an <see cref="ECParameters"/>
    /// for a named curve (any curve in <see cref="ECCurve.NamedCurves"/>, and any other named-curve
    /// OID the host BCL recognises). Returns <c>null</c> when the inputs don't decode as a
    /// DER-OCTET-wrapped uncompressed point or <c>CKA_EC_PARAMS</c> isn't a DER-encoded curve OID.
    /// </summary>
    /// <param name="ecPoint">Raw <c>CKA_EC_POINT</c> bytes (DER OCTET STRING containing the uncompressed point).</param>
    /// <param name="ecParams">Raw <c>CKA_EC_PARAMS</c> bytes (DER-encoded named-curve OID).</param>
    internal static ECParameters? TryParseEcPublicKey(byte[] ecPoint, byte[] ecParams)
    {
        ArgumentNullException.ThrowIfNull(ecPoint);
        ArgumentNullException.ThrowIfNull(ecParams);

        // CKA_EC_POINT is a DER-encoded OCTET STRING wrapping the uncompressed point.
        ReadOnlySpan<byte> pointBytes = StripDerOctetString(ecPoint);
        if (pointBytes.IsEmpty) return null;

        // Point format: 0x04 || X || Y for uncompressed.
        if (pointBytes[0] != 0x04) return null;
        int coordLen = (pointBytes.Length - 1) / 2;
        if (coordLen <= 0 || pointBytes.Length != 1 + 2 * coordLen) return null;

        byte[] x = pointBytes.Slice(1, coordLen).ToArray();
        byte[] y = pointBytes.Slice(1 + coordLen, coordLen).ToArray();

        if (ResolveNamedCurve(ecParams) is not { } curve) return null;
        return new ECParameters { Curve = curve, Q = new ECPoint { X = x, Y = y } };
    }

    /// <summary>
    /// Reads CKA_EC_POINT + CKA_EC_PARAMS from a CKO_PRIVATE_KEY object and returns the
    /// corresponding <see cref="ECParameters"/>. Returns <c>null</c> if either attribute
    /// is unreadable (per PKCS#11 v3.1, CKA_EC_POINT is optional on private-key
    /// objects).
    /// </summary>
    internal static ECParameters? TrySynthesizeEc(Pkcs11Session session, ObjectHandle privateHandle)
    {
        var attrs = session.GetAttributeValue(privateHandle,
        [
            CKA.CKA_EC_POINT,
            CKA.CKA_EC_PARAMS,
        ]);

        try
        {
            if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
                return null;
            return TryParseEcPublicKey(attrs[0].GetValueAsByteArray(), attrs[1].GetValueAsByteArray());
        }
        finally
        {
            foreach (var a in attrs) a.Dispose();
        }
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
    // over that OID. Covers the whole ECCurve.NamedCurves catalog (NIST, secp256k1, Brainpool, SM2),
    // not just the NIST primes. Returns null when the bytes aren't a DER-encoded OID.
    private static BclECCurve? ResolveNamedCurve(byte[] derOid)
    {
        try
        {
            return ECCurve.FromEcParams(derOid).ToECCurve();
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
