using System.Formats.Asn1;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// The RFC 3279 DER encoding of a DSA or ECDSA signature, converted to the r‖s form the token's
/// <c>CKM_DSA</c> and <c>CKM_ECDSA</c> mechanisms take, as the BCL's own conversion does.
/// </summary>
internal static class DssSignatureEncoding
{
    /// <summary>
    /// Converts a DER <c>Dss-Sig-Value { r, s }</c> to r‖s, each left-padded to <paramref name="fieldLength"/>
    /// bytes. Returns <see langword="null"/> when the encoding is malformed or a value does not fit, where the
    /// BCL's conversion throws and its caller returns false.
    /// </summary>
    public static byte[]? DerToIeeeP1363(ReadOnlySpan<byte> signature, int fieldLength)
    {
        try
        {
            AsnDecoder.ReadSequence(signature, AsnEncodingRules.DER, out int offset, out int length, out int consumed);
            if (consumed != signature.Length)
                return null;
            ReadOnlySpan<byte> sequence = signature.Slice(offset, length);
            ReadOnlySpan<byte> r = AsnDecoder.ReadIntegerBytes(sequence, AsnEncodingRules.DER, out consumed);
            sequence = sequence[consumed..];
            ReadOnlySpan<byte> s = AsnDecoder.ReadIntegerBytes(sequence, AsnEncodingRules.DER, out consumed);
            if (consumed != sequence.Length)
                return null;

            byte[] ieee = new byte[2 * fieldLength];
            return TryCopyField(r, ieee.AsSpan(0, fieldLength)) && TryCopyField(s, ieee.AsSpan(fieldLength))
                ? ieee
                : null;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    // A DER INTEGER is one byte longer than the field only for the zero that keeps a set high bit positive.
    private static bool TryCopyField(ReadOnlySpan<byte> field, Span<byte> destination)
    {
        if (field.Length > destination.Length)
        {
            if (field.Length != destination.Length + 1 || field is not [0, > 0x7F, ..])
                return false;
            field = field[1..];
        }
        field.CopyTo(destination[(destination.Length - field.Length)..]);
        return true;
    }
}
