using System.Diagnostics.CodeAnalysis;
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

/// <summary>
/// An immutable set of named elliptic curves the library knows the name and field size of. The field
/// size drives the checks and sizes of EC operations on token keys: the peer public key's coordinate
/// length in ECDH, the length of a raw ECDH secret, and <see cref="System.Security.Cryptography.AsymmetricAlgorithm.KeySize"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Default"/> holds every curve of <see cref="Pkcs11ECCurve.NamedCurves"/>. To teach the
/// library a curve outside it, derive a catalog with <see cref="With(Pkcs11CurveInfo)"/> and hand it to
/// <see cref="Pkcs11LibraryOptions.CurveCatalog"/>; every session of that library then resolves the
/// curve of a token key through it:
/// </para>
/// <code>
/// var catalog = Pkcs11CurveCatalog.Default.With(new Pkcs11CurveInfo("1.2.3.4", "myCurve", 256));
/// using var library = Pkcs11Library.Load(path, new Pkcs11LibraryOptions { CurveCatalog = catalog });
/// </code>
/// <para>
/// A catalog only describes curves; it does not permit them. Whether a key may be generated on a curve
/// is still the session's <see cref="Pkcs11Session.Policy"/> decision, and the strict policies refuse a
/// curve they don't list.
/// </para>
/// <para>A catalog never changes once built, so one instance can be shared across libraries and threads.</para>
/// </remarks>
public sealed class Pkcs11CurveCatalog
{
    private readonly Pkcs11CurveInfo[] _curves;
    private readonly Dictionary<string, Pkcs11CurveInfo> _byOid;
    private readonly Dictionary<string, Pkcs11CurveInfo> _byName;

    private Pkcs11CurveCatalog(Pkcs11CurveInfo[] curves)
    {
        _curves = curves;
        _byOid = curves.ToDictionary(c => c.Oid, StringComparer.Ordinal);
        _byName = curves.ToDictionary(c => c.Name, StringComparer.Ordinal);
    }

    /// <summary>
    /// The built-in catalog: every curve of <see cref="Pkcs11ECCurve.NamedCurves"/> — the NIST primes,
    /// the SEC 2 Koblitz curves, the Brainpool family (RFC 5639) and SM2.
    /// </summary>
    public static Pkcs11CurveCatalog Default { get; } = new(
    [
        new(Pkcs11ECCurve.NistP192Oid,        "nistP192",        192),
        new(Pkcs11ECCurve.NistP224Oid,        "nistP224",        224),
        new(Pkcs11ECCurve.NistP256Oid,        "nistP256",        256),
        new(Pkcs11ECCurve.NistP384Oid,        "nistP384",        384),
        new(Pkcs11ECCurve.NistP521Oid,        "nistP521",        521),
        new(Pkcs11ECCurve.Secp192k1Oid,       "secp192k1",       192),
        new(Pkcs11ECCurve.Secp224k1Oid,       "secp224k1",       224),
        new(Pkcs11ECCurve.Secp256k1Oid,       "secp256k1",       256),
        new(Pkcs11ECCurve.BrainpoolP160r1Oid, "brainpoolP160r1", 160),
        new(Pkcs11ECCurve.BrainpoolP160t1Oid, "brainpoolP160t1", 160),
        new(Pkcs11ECCurve.BrainpoolP192r1Oid, "brainpoolP192r1", 192),
        new(Pkcs11ECCurve.BrainpoolP192t1Oid, "brainpoolP192t1", 192),
        new(Pkcs11ECCurve.BrainpoolP224r1Oid, "brainpoolP224r1", 224),
        new(Pkcs11ECCurve.BrainpoolP224t1Oid, "brainpoolP224t1", 224),
        new(Pkcs11ECCurve.BrainpoolP256r1Oid, "brainpoolP256r1", 256),
        new(Pkcs11ECCurve.BrainpoolP256t1Oid, "brainpoolP256t1", 256),
        new(Pkcs11ECCurve.BrainpoolP320r1Oid, "brainpoolP320r1", 320),
        new(Pkcs11ECCurve.BrainpoolP320t1Oid, "brainpoolP320t1", 320),
        new(Pkcs11ECCurve.BrainpoolP384r1Oid, "brainpoolP384r1", 384),
        new(Pkcs11ECCurve.BrainpoolP384t1Oid, "brainpoolP384t1", 384),
        new(Pkcs11ECCurve.BrainpoolP512r1Oid, "brainpoolP512r1", 512),
        new(Pkcs11ECCurve.BrainpoolP512t1Oid, "brainpoolP512t1", 512),
        new(Pkcs11ECCurve.Sm2Oid,             "sm2",             256),
    ]);

    /// <summary>The curves of this catalog, built-in ones first, then in the order they were added.</summary>
    public IReadOnlyList<Pkcs11CurveInfo> Curves => _curves;

    /// <summary>
    /// Returns a new catalog with <paramref name="curve"/> added; this one is left unchanged.
    /// </summary>
    /// <remarks>
    /// A catalog only grows: an entry can't be replaced, so no catalog can redescribe a built-in curve
    /// (e.g. give P-256 another field size and weaken the checks that rely on it).
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="curve"/> is null.</exception>
    /// <exception cref="ArgumentException">The catalog already has a curve with the same OID or name.</exception>
    public Pkcs11CurveCatalog With(Pkcs11CurveInfo curve)
    {
        ArgumentNullException.ThrowIfNull(curve);
        if (_byOid.TryGetValue(curve.Oid, out Pkcs11CurveInfo? sameOid))
            throw new ArgumentException($"The catalog already has a curve with OID {curve.Oid} ({sameOid.Name}).", nameof(curve));
        if (_byName.TryGetValue(curve.Name, out Pkcs11CurveInfo? sameName))
            throw new ArgumentException($"The catalog already has a curve named {curve.Name} ({sameName.Oid}).", nameof(curve));
        return new Pkcs11CurveCatalog([.. _curves, curve]);
    }

    /// <summary>Looks up a curve by its dotted-decimal OID.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="oid"/> is null.</exception>
    public bool TryGetByOid(string oid, [NotNullWhen(true)] out Pkcs11CurveInfo? curve)
    {
        ArgumentNullException.ThrowIfNull(oid);
        return _byOid.TryGetValue(oid, out curve);
    }

    /// <summary>Looks up a curve by its friendly name (case-sensitive, e.g. <c>nistP256</c>).</summary>
    /// <exception cref="ArgumentNullException"><paramref name="name"/> is null.</exception>
    public bool TryGetByName(string name, [NotNullWhen(true)] out Pkcs11CurveInfo? curve)
    {
        ArgumentNullException.ThrowIfNull(name);
        return _byName.TryGetValue(name, out curve);
    }

    /// <summary>
    /// <paramref name="curve"/> with this catalog's name and field size when the catalog lists its OID;
    /// otherwise <paramref name="curve"/> unchanged. Used on a curve read off a token
    /// (<see cref="Pkcs11ECCurve.FromEcParams"/>), which carries only an OID.
    /// </summary>
    internal Pkcs11ECCurve Resolve(Pkcs11ECCurve curve)
        => curve.Oid is { } oid && _byOid.TryGetValue(oid, out Pkcs11CurveInfo? info) ? info.ToCurve() : curve;
}
