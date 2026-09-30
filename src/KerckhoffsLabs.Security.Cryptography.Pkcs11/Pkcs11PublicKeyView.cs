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
    /// Validates a peer's ECDH public key against <paramref name="localCurve"/> before it reaches
    /// <c>CKM_ECDH1_DERIVE</c>: the peer must be on that exact named curve, its coordinates must
    /// match the curve's field size, and the point itself must satisfy the curve equation.
    /// PKCS#11 does not require the token to check either the curve or the point, so skipping this
    /// lets a peer on a different (weaker) curve — or an off-curve point on the right curve — reach
    /// the token unchecked; the invalid-curve / small-subgroup attack then recovers a token-resident
    /// private key one residue at a time (Antipa et al., PKC 2003; NIST SP 800-56A Rev. 3 §5.6.2.3.2).
    /// </summary>
    /// <param name="localCurve">The local private key's curve, from <see cref="Pkcs11Key.GetEcCurve"/>.</param>
    /// <param name="peer">The peer's public key, as reported by the caller.</param>
    /// <param name="paramName">The caller's parameter to attribute a thrown exception to.</param>
    /// <exception cref="ArgumentException">
    /// Thrown if <paramref name="peer"/> has no X or Y coordinate, its curve does not match
    /// <paramref name="localCurve"/>, its coordinate lengths don't match that curve's field size, or
    /// the point does not satisfy the curve equation.
    /// </exception>
    internal static void ValidatePeerEcKey(Pkcs11ECCurve localCurve, ECParameters peer, string paramName)
    {
        byte[] x = peer.Q.X ?? throw new ArgumentException("Peer public key has no X coordinate.", paramName);
        byte[] y = peer.Q.Y ?? throw new ArgumentException("Peer public key has no Y coordinate.", paramName);

        string? peerOid = peer.Curve.Oid?.Value;
        if (peerOid is null || !string.Equals(peerOid, localCurve.Oid, StringComparison.Ordinal))
            throw new ArgumentException(
                $"Peer public key is on curve {peer.Curve.Oid?.FriendlyName ?? peerOid ?? "unknown"}, expected {localCurve.FriendlyName ?? localCurve.Oid}.",
                paramName);

        ValidatePoint(localCurve, x, y, paramName);
    }

    /// <summary>
    /// Validates the peer point carried by ECDH1-derive parameters against <paramref name="localCurve"/>,
    /// with the same checks as <see cref="ValidatePeerEcKey"/>. The point may be either form PKCS#11
    /// accepts for <c>pPublicData</c>: the raw uncompressed point, or the DER OCTET STRING wrapping it.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// Thrown if the point is not an uncompressed point of the curve's size, or does not satisfy the
    /// curve equation.
    /// </exception>
    internal static void ValidatePeerPoint(Pkcs11ECCurve localCurve, ReadOnlySpan<byte> publicData, string paramName)
    {
        ReadOnlySpan<byte> point = UnwrapPoint(publicData, localCurve.FieldSizeBits);
        int coordinateLength = (point.Length - 1) / 2;
        if (point.IsEmpty || point[0] != 0x04 || coordinateLength == 0 || point.Length != 1 + 2 * coordinateLength)
            throw new ArgumentException(
                "The peer public point must be an uncompressed EC point (04 ‖ X ‖ Y), raw or DER OCTET STRING-wrapped.",
                paramName);

        ValidatePoint(localCurve, point.Slice(1, coordinateLength).ToArray(), point.Slice(1 + coordinateLength).ToArray(), paramName);
    }

    // The raw form is taken when its length is exactly an uncompressed point of the curve's field size;
    // otherwise the DER wrapper is removed. Checking the raw length first matters: a raw point whose X
    // happens to start with a plausible DER length byte would otherwise be mis-read as a wrapped one.
    private static ReadOnlySpan<byte> UnwrapPoint(ReadOnlySpan<byte> publicData, int? fieldSizeBits)
    {
        if (fieldSizeBits is int bits && publicData.Length == 1 + 2 * ((bits + 7) / 8) && publicData[0] == 0x04)
            return publicData;
        ReadOnlySpan<byte> inner = StripDerOctetString(publicData);
        return inner.IsEmpty ? publicData : inner;
    }

    private static void ValidatePoint(Pkcs11ECCurve localCurve, byte[] x, byte[] y, string paramName)
    {
        // Skip when the local curve isn't one this library's catalog knows the field size for —
        // the point-on-curve check below still runs regardless.
        if (localCurve.FieldSizeBits is int bits)
        {
            int fieldSizeBytes = (bits + 7) / 8;
            if (x.Length != fieldSizeBytes || y.Length != fieldSizeBytes)
                throw new ArgumentException(
                    $"Peer coordinate length {x.Length}/{y.Length} bytes does not match the curve's {fieldSizeBytes}-byte field size.",
                    paramName);
        }

        // Both the OpenSSL and CNG backends reject an off-curve point on import, which is what
        // actually defends against a maliciously chosen point on the right curve. CNG's rejection
        // for some malformed points (e.g. the all-zero point) surfaces as PlatformNotSupportedException
        // ("curve ... not valid for this platform") wrapping a CryptographicException, not the
        // CryptographicException itself — catch both. The curve is the local key's, one the token
        // already holds a real key on, so a PlatformNotSupportedException here means "this point is
        // rejected", not "this curve is unsupported".
        try
        {
            using ECDiffieHellman probe = ECDiffieHellman.Create(new ECParameters
            {
                Curve = localCurve.ToECCurve(),
                Q = new ECPoint { X = x, Y = y },
            });
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
        {
            throw new ArgumentException("The peer public point does not satisfy the curve equation.", paramName, ex);
        }
    }

    private static ReadOnlySpan<byte> StripDerOctetString(ReadOnlySpan<byte> der)
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
        return der.Slice(offset, len);
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
