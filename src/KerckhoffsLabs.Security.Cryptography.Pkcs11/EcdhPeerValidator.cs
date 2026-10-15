using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A peer's ECDH public key that passed <see cref="EcdhPeerValidator.Validate"/>, with
/// <see cref="EncodedPoint"/> ready for the <c>CKM_ECDH1_DERIVE</c> public-data parameter.
/// </summary>
/// <param name="LocalCurve">The local key's curve, resolved through the library's curve catalog.</param>
/// <param name="X">The peer's X coordinate.</param>
/// <param name="Y">The peer's Y coordinate.</param>
/// <param name="EncodedPoint">The peer's point as a DER OCTET STRING (see <see cref="EcPointEncoding.Encode"/>).</param>
internal readonly record struct ValidatedEcdhPeer(Pkcs11ECCurve LocalCurve, byte[] X, byte[] Y, byte[] EncodedPoint);

/// <summary>
/// Validates a peer's ECDH public key against the local key before it reaches
/// <c>CKM_ECDH1_DERIVE</c>: the peer must be on that exact named curve, its coordinates must match the
/// curve's field size, and the point itself must satisfy the curve equation.
/// </summary>
/// <remarks>
/// PKCS#11 does not require the token to check either the curve or the point, so skipping this lets a
/// peer on a different (weaker) curve — or an off-curve point on the right curve — reach the token
/// unchecked; the invalid-curve / small-subgroup attack then recovers a token-resident private key one
/// residue at a time (Antipa et al., PKC 2003; NIST SP 800-56A Rev. 3 §5.6.2.3.2). The only way to the
/// encoded point a derivation needs is through <see cref="Validate"/>, so no caller can skip the checks.
/// </remarks>
internal static class EcdhPeerValidator
{
    /// <summary>Validates <paramref name="peer"/> against <paramref name="localKey"/>'s curve and encodes its point.</summary>
    /// <param name="localKey">The token-resident EC private key the agreement will use.</param>
    /// <param name="peer">The peer's public key, as reported by the caller.</param>
    /// <param name="peerParamName">The caller's parameter name for <paramref name="peer"/>, for a missing coordinate.</param>
    /// <param name="operationName">The operation name to attribute a thrown exception to.</param>
    /// <exception cref="ArgumentException"><paramref name="peer"/> has no X or Y coordinate.</exception>
    /// <exception cref="Pkcs11Exception">The local key's <c>CKA_EC_PARAMS</c> is unreadable.</exception>
    /// <exception cref="Pkcs11ArgumentException">
    /// <paramref name="peer"/>'s curve does not match the local key's, its coordinate lengths don't match
    /// that curve's field size, or the point does not satisfy the curve equation.
    /// </exception>
    internal static ValidatedEcdhPeer Validate(Pkcs11Key localKey, ECParameters peer, string peerParamName, string operationName)
    {
        byte[] x = peer.Q.X ?? throw new ArgumentException("Peer public key has no X coordinate.", peerParamName);
        byte[] y = peer.Q.Y ?? throw new ArgumentException("Peer public key has no Y coordinate.", peerParamName);

        Pkcs11ECCurve localCurve = ReadLocalCurve(localKey, operationName);
        CheckCurve(localCurve, peer, operationName);
        CheckCoordinateLength(localCurve, x, y, operationName);
        CheckPointOnCurve(peer, operationName);

        return new ValidatedEcdhPeer(localCurve, x, y, EcPointEncoding.Encode(x, y));
    }

    // Reads CKA_EC_PARAMS off the local key, resolved through the library's curve catalog so it carries
    // the curve's name and field size when the catalog lists it.
    private static Pkcs11ECCurve ReadLocalCurve(Pkcs11Key key, string operationName)
    {
        using var attrs = key.GetAttributeValue(CKA.CKA_EC_PARAMS);
        if (attrs.Count == 0 || attrs[0].CannotBeRead)
            throw Pkcs11Exception.Create(CKR.CKR_ATTRIBUTE_SENSITIVE,
                $"{operationName} (local CKA_EC_PARAMS not readable — cannot validate the peer's curve)");
        return key.Session.Library.CurveCatalog.Resolve(Pkcs11ECCurve.FromEcParams(attrs[0].GetValueAsByteArray()));
    }

    private static void CheckCurve(Pkcs11ECCurve localCurve, ECParameters peer, string operationName)
    {
        string? peerOid = peer.Curve.Oid.Value;
        if (peerOid is null || !string.Equals(peerOid, localCurve.Oid, StringComparison.Ordinal))
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"{operationName} (peer public key is on curve {peer.Curve.Oid.FriendlyName ?? peerOid ?? "unknown"}, expected {localCurve.FriendlyName ?? localCurve.Oid})");
    }

    // Skipped when the local curve isn't one the library's curve catalog knows the field size for —
    // CheckCurve already pins the peer to that exact (uncommon) curve, and CheckPointOnCurve still runs.
    private static void CheckCoordinateLength(Pkcs11ECCurve localCurve, byte[] x, byte[] y, string operationName)
    {
        if (localCurve.FieldSizeBits is not int bits) return;

        int fieldSizeBytes = (bits + 7) / 8;
        if (x.Length != fieldSizeBytes || y.Length != fieldSizeBytes)
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"{operationName} (peer coordinate length {x.Length}/{y.Length} bytes does not match the curve's {fieldSizeBytes}-byte field size)");
    }

    // Both the OpenSSL and CNG backends reject an off-curve point on import, which is what
    // actually defends against a maliciously chosen point on the right curve. CNG's rejection
    // for some malformed points (e.g. the all-zero point) surfaces as PlatformNotSupportedException
    // ("curve ... not valid for this platform") wrapping a CryptographicException, not the
    // CryptographicException itself — catch both. Reaching this point already means the curve
    // OID matched a curve this token just generated a real key on, so a PlatformNotSupportedException
    // here means "this point is rejected", not "this curve is unsupported".
    private static void CheckPointOnCurve(ECParameters peer, string operationName)
    {
        try
        {
            using ECDiffieHellman probe = ECDiffieHellman.Create(peer);
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
        {
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"{operationName} (peer public key point does not satisfy the curve equation)");
        }
    }
}
