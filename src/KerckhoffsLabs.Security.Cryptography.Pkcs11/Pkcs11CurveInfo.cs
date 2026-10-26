using System.Formats.Asn1;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// What the library knows about a named elliptic curve beyond its OID: a friendly name, the field size
/// and the size of the group order, in bits. One entry of a <see cref="Pkcs11CurveCatalog"/>.
/// </summary>
public sealed record Pkcs11CurveInfo
{
    /// <summary>Creates a curve entry whose group order is as long as its field, as on most curves.</summary>
    /// <param name="oid">The curve's dotted-decimal OID (e.g. <c>1.2.840.10045.3.1.7</c>).</param>
    /// <param name="name">The curve's friendly name (e.g. <c>nistP256</c>).</param>
    /// <param name="fieldSizeBits">The curve's field size in bits (e.g. 256 for P-256, 521 for P-521).</param>
    /// <exception cref="ArgumentNullException"><paramref name="oid"/> or <paramref name="name"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="oid"/> is not a valid OID, or <paramref name="name"/> is empty or whitespace.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="fieldSizeBits"/> is not positive.</exception>
    public Pkcs11CurveInfo(string oid, string name, int fieldSizeBits)
        : this(oid, name, fieldSizeBits, fieldSizeBits)
    {
    }

    /// <summary>Creates a curve entry with the size of its group order.</summary>
    /// <param name="oid">The curve's dotted-decimal OID (e.g. <c>1.2.840.10045.3.1.7</c>).</param>
    /// <param name="name">The curve's friendly name (e.g. <c>nistP256</c>).</param>
    /// <param name="fieldSizeBits">The curve's field size in bits (e.g. 256 for P-256, 521 for P-521).</param>
    /// <param name="orderSizeBits">
    /// The bit length of the curve's group order n (e.g. 225 for secp224k1, whose order is just above
    /// 2<sup>224</sup>). By Hasse's bound it is at most one more than <paramref name="fieldSizeBits"/>.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="oid"/> or <paramref name="name"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="oid"/> is not a valid OID, or <paramref name="name"/> is empty or whitespace.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="fieldSizeBits"/> or <paramref name="orderSizeBits"/> is not positive, or
    /// <paramref name="orderSizeBits"/> is more than one above <paramref name="fieldSizeBits"/>.
    /// </exception>
    public Pkcs11CurveInfo(string oid, string name, int fieldSizeBits, int orderSizeBits)
    {
        ArgumentNullException.ThrowIfNull(oid);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(fieldSizeBits);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(orderSizeBits);
        if (orderSizeBits - 1 > fieldSizeBits)
            throw new ArgumentOutOfRangeException(nameof(orderSizeBits), orderSizeBits, "The group order can be at most one bit longer than the field.");
        try
        {
            new AsnWriter(AsnEncodingRules.DER).WriteObjectIdentifier(oid);
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException($"'{oid}' is not a valid dotted-decimal OID.", nameof(oid), ex);
        }

        Oid = oid;
        Name = name;
        FieldSizeBits = fieldSizeBits;
        OrderSizeBits = orderSizeBits;
    }

    /// <summary>The curve's dotted-decimal OID.</summary>
    public string Oid { get; }

    /// <summary>The curve's friendly name.</summary>
    public string Name { get; }

    /// <summary>The curve's field size in bits; see <see cref="Pkcs11ECCurve.FieldSizeBits"/>.</summary>
    public int FieldSizeBits { get; }

    /// <summary>
    /// The bit length of the curve's group order n. An ECDSA signature's r and s are each
    /// <c>(OrderSizeBits + 7) / 8</c> bytes in the r‖s form a token signs and verifies with
    /// <c>CKM_ECDSA</c>: 29 for secp224k1 and 21 for the secp160 curves, where the field takes one byte
    /// less.
    /// </summary>
    public int OrderSizeBits { get; }

    /// <summary>A <see cref="Pkcs11ECCurve"/> over this OID that carries this entry's name and field size.</summary>
    public Pkcs11ECCurve ToCurve() => Pkcs11ECCurve.FromInfo(this);
}
