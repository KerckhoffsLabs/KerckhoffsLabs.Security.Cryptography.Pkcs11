using System.Formats.Asn1;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// What the library knows about a named elliptic curve beyond its OID: a friendly name and the field
/// size in bits. One entry of a <see cref="Pkcs11CurveCatalog"/>.
/// </summary>
public sealed record Pkcs11CurveInfo
{
    /// <summary>Creates a curve entry.</summary>
    /// <param name="oid">The curve's dotted-decimal OID (e.g. <c>1.2.840.10045.3.1.7</c>).</param>
    /// <param name="name">The curve's friendly name (e.g. <c>nistP256</c>).</param>
    /// <param name="fieldSizeBits">The curve's field size in bits (e.g. 256 for P-256, 521 for P-521).</param>
    /// <exception cref="ArgumentNullException"><paramref name="oid"/> or <paramref name="name"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="oid"/> is not a valid OID, or <paramref name="name"/> is empty or whitespace.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="fieldSizeBits"/> is not positive.</exception>
    public Pkcs11CurveInfo(string oid, string name, int fieldSizeBits)
    {
        ArgumentNullException.ThrowIfNull(oid);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(fieldSizeBits);
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
    }

    /// <summary>The curve's dotted-decimal OID.</summary>
    public string Oid { get; }

    /// <summary>The curve's friendly name.</summary>
    public string Name { get; }

    /// <summary>The curve's field size in bits; see <see cref="Pkcs11ECCurve.FieldSizeBits"/>.</summary>
    public int FieldSizeBits { get; }

    /// <summary>A <see cref="Pkcs11ECCurve"/> over this OID that carries this entry's name and field size.</summary>
    public Pkcs11ECCurve ToCurve() => Pkcs11ECCurve.FromInfo(this);
}
