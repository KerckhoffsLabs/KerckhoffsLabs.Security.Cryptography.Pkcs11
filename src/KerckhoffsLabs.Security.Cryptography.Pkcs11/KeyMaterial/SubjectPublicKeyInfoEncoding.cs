using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;

/// <summary>
/// The X.509 <c>SubjectPublicKeyInfo</c> encoding of a public key (RFC 5280 §4.1.2.7), both directions:
/// <c>SEQUENCE { AlgorithmIdentifier, BIT STRING subjectPublicKey }</c>.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>EC (RFC 5480): algorithm <c>id-ecPublicKey</c>, parameters the <i>namedCurve</i> OID, and the
/// uncompressed point <c>0x04 ‖ X ‖ Y</c> as the BIT STRING.</item>
/// <item>RSA (RFC 8017 §A.1, RFC 3279 §2.3.1): algorithm <c>rsaEncryption</c> with NULL parameters, and the
/// PKCS#1 <c>RSAPublicKey</c> as the BIT STRING.</item>
/// <item>DSA (RFC 3279 §2.3.2): algorithm <c>id-dsa</c> with <c>Dss-Parms ::= SEQUENCE { p, q, g }</c>, and
/// the public value <c>INTEGER y</c> as the BIT STRING.</item>
/// <item>ML-DSA, SLH-DSA, ML-KEM: the parameter set's OID with absent parameters, and the FIPS-encoded
/// public key as the BIT STRING (see <see cref="PostQuantumParameterSets"/>).</item>
/// </list>
/// Writes and reads DER only: a peer key is caller input, so nothing outside the canonical encoding is
/// accepted.
/// </remarks>
internal static class SubjectPublicKeyInfoEncoding
{
    private static readonly byte[] DerNull = [0x05, 0x00];

    /// <summary>Encodes a named-curve EC public key.</summary>
    internal static byte[] EncodeEc(ECParameters ec)
        => Encode(Oids.KeyAlgorithms.EcPublicKey, Pkcs11ECCurve.FromECCurve(ec.Curve).GetEcParams(), EcPointEncoding.EncodeUncompressedPoint(ec.Q.X, ec.Q.Y));

    /// <summary>Encodes an RSA public key from its unsigned big-endian modulus and public exponent.</summary>
    internal static byte[] EncodeRsa(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent)
        => Encode(Oids.KeyAlgorithms.RsaEncryption, DerNull, EncodeRsaPublicKey(modulus, exponent));

    /// <summary>
    /// The PKCS#1 <c>RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }</c>, what
    /// <see cref="RSA.ExportRSAPublicKey"/> writes.
    /// </summary>
    internal static byte[] EncodeRsaPublicKey(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            // PKCS#11 big integers are unsigned big-endian and may carry leading zero bytes, which DER's
            // minimal INTEGER encoding forbids.
            writer.WriteIntegerUnsigned(TrimLeadingZeros(modulus));
            writer.WriteIntegerUnsigned(TrimLeadingZeros(exponent));
        }
        return writer.Encode();
    }

    /// <summary>Encodes a public key whose algorithm takes no parameters (ML-DSA, SLH-DSA, ML-KEM).</summary>
    internal static byte[] EncodeWithoutParameters(string algorithmOid, ReadOnlySpan<byte> publicKey)
        => Encode(algorithmOid, null, publicKey);

    /// <summary>Encodes a DSA public key from its unsigned big-endian domain parameters and public value.</summary>
    internal static byte[] EncodeDsa(ReadOnlySpan<byte> p, ReadOnlySpan<byte> q, ReadOnlySpan<byte> g, ReadOnlySpan<byte> y)
    {
        var parameters = new AsnWriter(AsnEncodingRules.DER);
        using (parameters.PushSequence())
        {
            parameters.WriteIntegerUnsigned(TrimLeadingZeros(p));
            parameters.WriteIntegerUnsigned(TrimLeadingZeros(q));
            parameters.WriteIntegerUnsigned(TrimLeadingZeros(g));
        }
        return Encode(Oids.KeyAlgorithms.Dsa, parameters.Encode(), EncodeDsaPublicKey(y));
    }

    /// <summary>The DSA public value as RFC 3279's <c>DSAPublicKey ::= INTEGER</c>.</summary>
    internal static byte[] EncodeDsaPublicKey(ReadOnlySpan<byte> y)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteIntegerUnsigned(TrimLeadingZeros(y));
        return writer.Encode();
    }

    // The BCL writes the outer structure. parameters is the encoded AlgorithmIdentifier parameters, or
    // null to leave them absent, as the post-quantum algorithms need; RSA's NULL is passed as 05 00.
    private static byte[] Encode(string algorithmOid, byte[]? parameters, ReadOnlySpan<byte> subjectPublicKey)
        => new PublicKey(
            new Oid(algorithmOid, null),
            parameters is null ? null : new AsnEncodedData(parameters),
            new AsnEncodedData(subjectPublicKey)).ExportSubjectPublicKeyInfo();

    // An all-zero or empty value is the INTEGER 0.
    private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
    {
        int i = value.IndexOfAnyExcept((byte)0);
        return i < 0 ? [0] : value[i..];
    }

    /// <summary>
    /// Reads the algorithm OID of a DER <c>SubjectPublicKeyInfo</c>, or <see langword="null"/> when the
    /// bytes are not one.
    /// </summary>
    internal static string? TryReadAlgorithm(ReadOnlySpan<byte> spki)
        => TryRead(spki, out string? algorithm, out _, out _) ? algorithm : null;

    /// <summary>
    /// Decodes an RFC 5480 EC public key: <c>id-ecPublicKey</c>, a <i>namedCurve</i> OID and an
    /// uncompressed point with coordinates of equal length. Returns <see langword="false"/> for anything
    /// else, including compressed points and explicit curve parameters.
    /// </summary>
    internal static bool TryDecodeEc(ReadOnlySpan<byte> spki, out ECParameters ec)
    {
        ec = default;
        if (!TryRead(spki, out string? algorithm, out ReadOnlySpan<byte> parameters, out byte[]? key)
            || algorithm != Oids.KeyAlgorithms.EcPublicKey
            || !EcPointEncoding.TryResolveNamedCurve(parameters, out ECCurve curve)
            || !EcPointEncoding.TrySplitUncompressedPoint(key, out byte[] x, out byte[] y))
            return false;

        ec = new ECParameters { Curve = curve, Q = new ECPoint { X = x, Y = y } };
        return true;
    }

    /// <summary>
    /// Decodes a public key whose algorithm takes no parameters (RFC 8410 §3 for X25519 / X448: the
    /// parameters MUST be absent): the algorithm OID and the BIT STRING's bytes. Returns
    /// <see langword="false"/> when the bytes are not a DER <c>SubjectPublicKeyInfo</c> or carry parameters.
    /// </summary>
    internal static bool TryDecodeWithoutParameters(ReadOnlySpan<byte> spki, [NotNullWhen(true)] out string? algorithm, [NotNullWhen(true)] out byte[]? publicKey)
    {
        if (TryRead(spki, out algorithm, out ReadOnlySpan<byte> parameters, out publicKey) && parameters.IsEmpty)
            return true;
        algorithm = null;
        publicKey = null;
        return false;
    }

    // Not PublicKey.CreateFromSubjectPublicKeyInfo: it ignores the BIT STRING's unused-bits count, and a
    // peer key is caller input. Every level must be consumed exactly. parameters is empty when absent: a
    // present one is at least a tag and a length.
    private static bool TryRead(
        ReadOnlySpan<byte> spki, [NotNullWhen(true)] out string? algorithm, out ReadOnlySpan<byte> parameters, [NotNullWhen(true)] out byte[]? key)
    {
        algorithm = null;
        parameters = default;
        key = null;
        try
        {
            AsnDecoder.ReadSequence(spki, AsnEncodingRules.DER, out int offset, out int length, out int consumed);
            if (consumed != spki.Length)
                return false;
            ReadOnlySpan<byte> info = spki.Slice(offset, length);

            AsnDecoder.ReadSequence(info, AsnEncodingRules.DER, out offset, out length, out consumed);
            ReadOnlySpan<byte> algorithmIdentifier = info.Slice(offset, length);
            info = info[consumed..];
            algorithm = AsnDecoder.ReadObjectIdentifier(algorithmIdentifier, AsnEncodingRules.DER, out consumed);
            parameters = algorithmIdentifier[consumed..];
            if (!parameters.IsEmpty)
            {
                AsnDecoder.ReadEncodedValue(parameters, AsnEncodingRules.DER, out _, out _, out consumed);
                if (consumed != parameters.Length)
                    return false;
            }

            key = AsnDecoder.ReadBitString(info, AsnEncodingRules.DER, out int unusedBits, out consumed);
            return consumed == info.Length && unusedBits == 0;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }
}
