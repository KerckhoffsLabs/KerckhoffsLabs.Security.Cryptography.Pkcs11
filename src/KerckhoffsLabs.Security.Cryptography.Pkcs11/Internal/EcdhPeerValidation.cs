using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// Checks the peer public point of an ECDH derivation against the local key's curve before it reaches
/// <c>CKM_ECDH1_DERIVE</c>: the peer must not name another curve, its coordinates must match the
/// curve's field size, and the point must satisfy the curve equation.
/// </summary>
/// <remarks>
/// PKCS#11 does not require the token to check either the curve or the point, so skipping this lets a
/// peer on a different (weaker) curve — or an off-curve point on the right curve — reach the token
/// unchecked; the invalid-curve / small-subgroup attack then recovers a token-resident private key one
/// residue at a time (Antipa et al., PKC 2003; NIST SP 800-56A Rev. 3 §5.6.2.3.2). Called by the
/// session on every ECDH derivation, whichever public entry point it came through.
/// </remarks>
internal static class EcdhPeerValidation
{
    /// <summary>Validates <paramref name="parameters"/>' peer against <paramref name="localCurve"/>.</summary>
    /// <param name="localCurve">The local private key's curve.</param>
    /// <param name="parameters">The derivation's parameters; the point may be raw or DER OCTET STRING-wrapped, as PKCS#11 allows.</param>
    /// <param name="paramName">The caller's parameter to attribute a thrown exception to.</param>
    /// <exception cref="ArgumentException">
    /// The peer names another curve, its point is not an uncompressed point of the curve's size, or the
    /// point does not satisfy the curve equation.
    /// </exception>
    internal static void Validate(Pkcs11ECCurve localCurve, CkmEcdh1DeriveParams parameters, string paramName)
    {
        if (parameters.PeerCurve is { } peerCurve && peerCurve != localCurve)
            throw new ArgumentException(
                $"Peer public key is on curve {peerCurve.FriendlyName ?? peerCurve.Oid}, expected {localCurve.FriendlyName ?? localCurve.Oid}.",
                paramName);

        ReadOnlySpan<byte> point = UnwrapPoint(parameters.PublicData, localCurve.FieldSizeBits);
        int coordinateLength = (point.Length - 1) / 2;
        if (point.IsEmpty || point[0] != 0x04 || coordinateLength == 0 || point.Length != 1 + 2 * coordinateLength)
            throw new ArgumentException(
                "The peer public point must be an uncompressed EC point (04 ‖ X ‖ Y), raw or DER OCTET STRING-wrapped.",
                paramName);

        // Skipped when the local curve isn't one this library's catalog knows the field size for; the
        // point-on-curve check below still runs regardless.
        if (localCurve.FieldSizeBits is int bits && coordinateLength != (bits + 7) / 8)
            throw new ArgumentException(
                $"Peer coordinates are {coordinateLength} bytes; the curve's field size is {(bits + 7) / 8} bytes.",
                paramName);

        // Both the OpenSSL and CNG backends reject an off-curve point on import, which is what actually
        // defends against a maliciously chosen point on the right curve. CNG's rejection for some
        // malformed points (e.g. the all-zero point) surfaces as PlatformNotSupportedException ("curve ...
        // not valid for this platform") wrapping a CryptographicException, not the CryptographicException
        // itself — catch both. The curve is the local key's, one the token already holds a real key on,
        // so a PlatformNotSupportedException here means "this point is rejected", not "this curve is
        // unsupported".
        try
        {
            using ECDiffieHellman probe = ECDiffieHellman.Create(new ECParameters
            {
                Curve = localCurve.ToECCurve(),
                Q = new ECPoint
                {
                    X = point.Slice(1, coordinateLength).ToArray(),
                    Y = point.Slice(1 + coordinateLength).ToArray(),
                },
            });
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
        {
            throw new ArgumentException("The peer public point does not satisfy the curve equation.", paramName, ex);
        }
    }

    // The raw form is taken when its length is exactly an uncompressed point of the curve's field size;
    // otherwise the DER wrapper is removed. Checking the raw length first matters: a raw point whose X
    // happens to start with a plausible DER length byte would otherwise be mis-read as a wrapped one.
    private static ReadOnlySpan<byte> UnwrapPoint(ReadOnlySpan<byte> publicData, int? fieldSizeBits)
    {
        if (fieldSizeBits is int bits && publicData.Length == 1 + 2 * ((bits + 7) / 8) && publicData[0] == 0x04)
            return publicData;
        ReadOnlySpan<byte> inner = Pkcs11PublicKeyView.StripDerOctetString(publicData);
        return inner.IsEmpty ? publicData : inner;
    }
}
