using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
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
        using var attrs = session.GetAttributeValue(privateHandle,
        [
            CKA.CKA_MODULUS,
            CKA.CKA_PUBLIC_EXPONENT,
        ]);
        if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
            return null;

        return new RSAParameters
        {
            Modulus = attrs[0].GetValueAsByteArray(),
            Exponent = attrs[1].GetValueAsByteArray(),
        };
    }

    /// <summary>
    /// Parses raw <c>CKA_EC_POINT</c> + <c>CKA_EC_PARAMS</c> bytes into an <see cref="ECParameters"/>
    /// for a named curve (any curve in <see cref="Pkcs11ECCurve.NamedCurves"/>, and any other named-curve
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
        using var attrs = session.GetAttributeValue(privateHandle,
        [
            CKA.CKA_EC_POINT,
            CKA.CKA_EC_PARAMS,
        ]);
        if (attrs[0].CannotBeRead || attrs[1].CannotBeRead)
            return null;
        return TryParseEcPublicKey(attrs[0].GetValueAsByteArray(), attrs[1].GetValueAsByteArray());
    }

    /// <summary>
    /// Reads <c>CKA_EC_PARAMS</c> off <paramref name="key"/> and parses it into a
    /// <see cref="Pkcs11ECCurve"/>. Used to establish the curve a peer's public key must match
    /// before an ECDH agreement reaches the token — see <see cref="ValidatePeerEcKey"/>.
    /// </summary>
    /// <param name="key">The token-resident EC key whose curve is being established.</param>
    /// <param name="operationName">The operation name to attribute a thrown exception to.</param>
    /// <exception cref="Pkcs11Exception">Thrown if <c>CKA_EC_PARAMS</c> is unreadable.</exception>
    /// <exception cref="ArgumentException">Thrown if <c>CKA_EC_PARAMS</c> is not a DER-encoded curve OID.</exception>
    internal static Pkcs11ECCurve GetCurve(Pkcs11Key key, string operationName)
    {
        using var attrs = key.GetAttributeValue(CKA.CKA_EC_PARAMS);
        if (attrs.Count == 0 || attrs[0].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                $"{operationName} (local CKA_EC_PARAMS not readable — cannot validate the peer's curve)");
        return Pkcs11ECCurve.FromEcParams(attrs[0].GetValueAsByteArray());
    }

    /// <summary>
    /// Validates a peer's ECDH public key against <paramref name="localCurve"/> before it reaches
    /// <c>CKM_ECDH1_DERIVE</c>: the peer must be on that exact named curve, its coordinates must
    /// match the curve's field size, and the point itself must satisfy the curve equation.
    /// PKCS#11 does not require the token to check either the curve or the point, so skipping this
    /// lets a peer on a different (weaker) curve — or an off-curve point on the right curve — reach
    /// the token unchecked; the invalid-curve / small-subgroup attack then recovers a token-resident
    /// private key one residue at a time (Antipa et al., PKC 2003; NIST SP 800-56A Rev. 3 §5.6.2.3.2).
    /// </summary>
    /// <param name="localCurve">The local private key's curve, from <see cref="GetCurve"/>.</param>
    /// <param name="peer">The peer's public key, as reported by the caller.</param>
    /// <param name="x">The peer's X coordinate (already null-checked by the caller).</param>
    /// <param name="y">The peer's Y coordinate (already null-checked by the caller).</param>
    /// <param name="operationName">The operation name to attribute a thrown exception to.</param>
    /// <exception cref="Pkcs11ArgumentException">
    /// Thrown if <paramref name="peer"/>'s curve does not match <paramref name="localCurve"/>, its
    /// coordinate lengths don't match that curve's field size, or the point does not satisfy the
    /// curve equation.
    /// </exception>
    internal static void ValidatePeerEcKey(Pkcs11ECCurve localCurve, ECParameters peer, byte[] x, byte[] y, string operationName)
    {
        string? peerOid = peer.Curve.Oid.Value;
        if (peerOid is null || !string.Equals(peerOid, localCurve.Oid, StringComparison.Ordinal))
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"{operationName} (peer public key is on curve {peer.Curve.Oid.FriendlyName ?? peerOid ?? "unknown"}, expected {localCurve.FriendlyName ?? localCurve.Oid})");

        // Skip when the local curve isn't one this library's catalog knows the field size for —
        // the OID-equality check above already pins the peer to that exact (uncommon) curve, and
        // the point-on-curve check below still runs regardless.
        if (localCurve.FieldSizeBits is int bits)
        {
            int fieldSizeBytes = (bits + 7) / 8;
            if (x.Length != fieldSizeBytes || y.Length != fieldSizeBytes)
                throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                    $"{operationName} (peer coordinate length {x.Length}/{y.Length} bytes does not match the curve's {fieldSizeBytes}-byte field size)");
        }

        // Both the OpenSSL and CNG backends reject an off-curve point on import, which is what
        // actually defends against a maliciously chosen point on the right curve.
        try
        {
            using ECDiffieHellman probe = ECDiffieHellman.Create(peer);
        }
        catch (CryptographicException)
        {
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"{operationName} (peer public key point does not satisfy the curve equation)");
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
