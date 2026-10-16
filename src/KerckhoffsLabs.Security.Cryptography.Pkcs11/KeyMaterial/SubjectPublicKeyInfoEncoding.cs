using System.Formats.Asn1;
using System.Security.Cryptography;

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
/// </list>
/// Writes and reads DER only: a peer key is caller input, so nothing outside the canonical encoding is
/// accepted.
/// </remarks>
internal static class SubjectPublicKeyInfoEncoding
{
    /// <summary><c>id-ecPublicKey</c> (RFC 5480 §2.1.1).</summary>
    internal const string EcPublicKeyOid = "1.2.840.10045.2.1";

    /// <summary><c>rsaEncryption</c> (RFC 8017 §A.1).</summary>
    internal const string RsaEncryptionOid = "1.2.840.113549.1.1.1";

    /// <summary>Encodes a named-curve EC public key.</summary>
    internal static byte[] EncodeEc(ECParameters ec)
        => Encode(EcPublicKeyOid, w => w.WriteObjectIdentifier(ec.Curve.Oid.Value!), [0x04, .. ec.Q.X!, .. ec.Q.Y!]);

    /// <summary>Encodes an RSA public key from its unsigned big-endian modulus and public exponent.</summary>
    internal static byte[] EncodeRsa(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent)
        => Encode(RsaEncryptionOid, w => w.WriteNull(), EncodeRsaPublicKey(modulus, exponent));

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

    private static byte[] Encode(string algorithmOid, Action<AsnWriter> writeParameters, ReadOnlySpan<byte> subjectPublicKey)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(algorithmOid);
                writeParameters(writer);
            }
            writer.WriteBitString(subjectPublicKey);
        }
        return writer.Encode();
    }

    private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
    {
        int i = value.IndexOfAnyExcept((byte)0);
        return i < 0 ? value[^1..] : value[i..];
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
        if (!TryRead(spki, out string? algorithm, out ReadOnlyMemory<byte>? parameters, out byte[]? key)
            || algorithm != EcPublicKeyOid || parameters is not { } p)
            return false;

        string curveOid;
        try
        {
            var reader = new AsnReader(p, AsnEncodingRules.DER);
            curveOid = reader.ReadObjectIdentifier();
            reader.ThrowIfNotEmpty();
        }
        catch (AsnContentException)
        {
            return false;
        }

        if (key is not [0x04, ..] || key.Length < 3 || key.Length % 2 == 0)
            return false;
        int coordinateLength = (key.Length - 1) / 2;
        ec = new ECParameters
        {
            Curve = ECCurve.CreateFromValue(curveOid),
            Q = new ECPoint { X = key[1..(1 + coordinateLength)], Y = key[(1 + coordinateLength)..] },
        };
        return true;
    }

    private static bool TryRead(ReadOnlySpan<byte> spki, out string? algorithm, out ReadOnlyMemory<byte>? parameters, out byte[]? key)
    {
        algorithm = null;
        parameters = null;
        key = null;
        try
        {
            var outer = new AsnReader(spki.ToArray(), AsnEncodingRules.DER);
            AsnReader info = outer.ReadSequence();
            outer.ThrowIfNotEmpty();

            AsnReader algorithmIdentifier = info.ReadSequence();
            algorithm = algorithmIdentifier.ReadObjectIdentifier();
            if (algorithmIdentifier.HasData)
                parameters = algorithmIdentifier.ReadEncodedValue();
            algorithmIdentifier.ThrowIfNotEmpty();

            key = info.ReadBitString(out int unusedBits);
            info.ThrowIfNotEmpty();
            if (unusedBits != 0)
                return false;
            return true;
        }
        catch (AsnContentException)
        {
            algorithm = null;
            return false;
        }
    }
}
