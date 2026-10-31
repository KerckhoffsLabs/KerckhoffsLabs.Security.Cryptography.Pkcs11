using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

/// <summary>
/// A peer's ECDH public key that passed <see cref="EcdhPeerValidator.Validate"/>, with
/// <see cref="EncodedPoint"/> ready for the <c>CKM_ECDH1_DERIVE</c> public-data parameter.
/// </summary>
/// <param name="FieldSizeBytes">
/// The local key's field size in bytes (⌈bits / 8⌉): the length of each peer coordinate and of the raw
/// shared secret. Never taken from the peer while the local key or the curve catalog can supply it.
/// </param>
/// <param name="X">The peer's X coordinate.</param>
/// <param name="Y">The peer's Y coordinate.</param>
/// <param name="EncodedPoint">The peer's point as a DER OCTET STRING (see <see cref="EcPointEncoding.Encode"/>).</param>
internal readonly record struct ValidatedEcdhPeer(int FieldSizeBytes, byte[] X, byte[] Y, byte[] EncodedPoint);

/// <summary>
/// Validates a peer's ECDH public key against the local key before it reaches
/// <c>CKM_ECDH1_DERIVE</c>: the peer must be on that exact named curve, its coordinates must match the
/// curve's field size, and the point itself must satisfy the curve equation.
/// </summary>
/// <remarks>
/// PKCS#11 does not require the token to check either the curve or the point, so skipping this lets a
/// peer on a different (weaker) curve — or an off-curve point on the right curve — reach the token
/// unchecked; the invalid-curve / small-subgroup attack then recovers a token-resident private key one
/// residue at a time (Antipa et al., PKC 2003; NIST SP 800-56A Rev. 3 §5.6.2.3.2). Every path that
/// takes the peer with its curve (<see cref="Pkcs11Key.DeriveRawSecret"/>,
/// <see cref="Pkcs11Session.DeriveSharedSecretEcdh(Pkcs11Key, ECParameters, int, CKD)"/>) reaches the
/// encoded point only through <see cref="Validate"/>. The paths that take an already-encoded point
/// (the <see cref="ReadOnlySpan{T}"/> overload of <c>DeriveSharedSecretEcdh</c>, or
/// <see cref="MechanismParams.CkmEcdh1DeriveParams"/> with <see cref="Pkcs11Key.Derive(Mechanism, Objects.ObjectTemplate)"/>) cannot be
/// checked, since an octet string carries no curve, and are documented as caller-validated.
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
        int fieldSizeBytes = ResolveFieldSizeBytes(localKey, localCurve, x);
        CheckCoordinateLength(fieldSizeBytes, x, y, operationName);
        CheckPointOnCurve(peer, operationName);

        return new ValidatedEcdhPeer(fieldSizeBytes, x, y, EcPointEncoding.Encode(x, y));
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

    // A peer with explicit curve parameters has no Oid at all, and never matches a named local curve.
    private static void CheckCurve(Pkcs11ECCurve localCurve, ECParameters peer, string operationName)
    {
        string? peerOid = peer.Curve.Oid?.Value;
        if (peerOid is null || !string.Equals(peerOid, localCurve.Oid, StringComparison.Ordinal))
            throw Pkcs11Exception.Create(CKR.CKR_ARGUMENTS_BAD,
                $"{operationName} (peer public key is on curve {peer.Curve.Oid?.FriendlyName ?? peerOid ?? "unknown"}, expected {localCurve.FriendlyName ?? localCurve.Oid})");
    }

    // The field size in bytes, from the most trusted source available:
    //   1. the library's curve catalog (exact bits, rounded up: P-521's 521-bit field takes 66 bytes);
    //   2. the local key's own CKA_EC_POINT, whose coordinates the token encodes at the field's byte
    //      length — covers a curve outside the catalog without the caller having to register it;
    //   3. the peer's X, only when the token exposes no readable CKA_EC_POINT on either handle. CheckCurve
    //      has pinned the peer to the local curve and CheckPointOnCurve still runs, but a peer that strips
    //      a leading zero from X can then shorten the derived secret.
    private static int ResolveFieldSizeBytes(Pkcs11Key key, Pkcs11ECCurve localCurve, byte[] x)
    {
        if (localCurve.FieldSizeBits is int bits)
            return (bits + 7) / 8;

        using var attrs = key.GetAttributeValue(CKA.CKA_EC_POINT);
        if (attrs.Count > 0 && !attrs[0].CannotBeRead
            && EcPointEncoding.TryGetCoordinateLength(attrs[0].GetValueAsByteArray(), out int coordinateLength))
            return coordinateLength;

        return x.Length;
    }

    private static void CheckCoordinateLength(int fieldSizeBytes, byte[] x, byte[] y, string operationName)
    {
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
