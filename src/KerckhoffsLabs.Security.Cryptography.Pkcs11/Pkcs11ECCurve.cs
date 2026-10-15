using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Identifies a named elliptic curve by its object identifier (OID), mirroring the shape of the BCL
/// <see cref="ECCurve"/>. A PKCS#11 EC key pair selects its curve through
/// the <c>CKA_EC_PARAMS</c> attribute, which for a named curve is the DER-encoded curve OID — exposed
/// here via <see cref="GetEcParams"/>.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="NamedCurves"/> nested class provides the prime-field (Weierstrass) curves a PKCS#11
/// v3.2 token may implement via <c>CKM_EC_KEY_PAIR_GEN</c> — the NIST primes, the Koblitz curves
/// (secp192k1/secp224k1/secp256k1), the Brainpool family (RFC 5639), and SM2. Any other curve can be selected with
/// <see cref="CreateFromValue(string, string?, int?)"/>, and described to the library (name, field size) through a
/// <see cref="Pkcs11CurveCatalog"/>. Twisted-Edwards (Ed25519/Ed448) and Montgomery
/// (X25519/X448) curves use different key types and key-pair-gen mechanisms and are intentionally
/// outside this type.
/// </para>
/// <para>This is a value type; the uninitialized <see langword="default"/> has no OID and throws from
/// <see cref="GetEcParams"/>.</para>
/// </remarks>
public readonly partial struct Pkcs11ECCurve : IEquatable<Pkcs11ECCurve>
{
    private readonly byte[]? _ecParams;
    private readonly int? _fieldSizeBits;

    private Pkcs11ECCurve(string oid, string? friendlyName, int? fieldSizeBits = null)
    {
        Oid = oid;
        FriendlyName = friendlyName;
        _fieldSizeBits = fieldSizeBits ?? (Pkcs11CurveCatalog.Default.TryGetByOid(oid, out Pkcs11CurveInfo? info) ? info.FieldSizeBits : null);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteObjectIdentifier(oid);
        _ecParams = writer.Encode();
    }

    /// <summary>The curve's object identifier in dotted-decimal form (e.g. <c>1.2.840.10045.3.1.7</c>).</summary>
    public string? Oid { get; }

    /// <summary>A human-readable name (e.g. <c>nistP256</c>), when known; otherwise <see langword="null"/>.</summary>
    public string? FriendlyName { get; }

    /// <summary>
    /// The category of this curve. Every curve this type can represent is a named curve and reports
    /// <see cref="ECCurve.ECCurveType.Named"/>; the uninitialized <see langword="default"/> reports
    /// <see cref="ECCurve.ECCurveType.Implicit"/>.
    /// </summary>
    public ECCurve.ECCurveType CurveType => Oid is null ? ECCurve.ECCurveType.Implicit : ECCurve.ECCurveType.Named;

    /// <summary>True when this instance names a curve (the only kind PKCS#11 selects by OID).</summary>
    public bool IsNamed => CurveType == ECCurve.ECCurveType.Named;

    /// <summary>True for the uninitialized <c>default(Pkcs11ECCurve)</c>, which carries no OID.</summary>
    public bool IsDefault => Oid is null;

    /// <summary>
    /// The curve's field size in bits (e.g. 256 for NIST P-256, 521 for P-521) when known: for a curve
    /// of <see cref="Pkcs11CurveCatalog.Default"/> (every curve of <see cref="NamedCurves"/>), or one
    /// created with a field size (<see cref="CreateFromValue(string, string?, int?)"/>,
    /// <see cref="Pkcs11CurveInfo.ToCurve"/>). Otherwise <see langword="null"/>, including for the
    /// uninitialized <see langword="default"/>: the field size of an arbitrary OID can't be inferred
    /// without decoding its domain parameters, which this type does not do.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the key size the BCL reports for the curve (<see cref="AsymmetricAlgorithm.KeySize"/>).
    /// A coordinate, and a raw ECDH shared secret, is <c>(FieldSizeBits + 7) / 8</c> bytes: 66 for P-521,
    /// not 521 / 8.
    /// </para>
    /// <para>
    /// Not part of equality, which compares OIDs only. A curve read off a token
    /// (<see cref="FromEcParams"/>) knows only the field size of a built-in curve; a token key's curve
    /// is resolved through the library's <see cref="Pkcs11LibraryOptions.CurveCatalog"/>.
    /// </para>
    /// </remarks>
    public int? FieldSizeBits => _fieldSizeBits;

    /// <summary>
    /// Gets the <c>CKA_EC_PARAMS</c> value for this curve: the DER encoding of the curve OID as an
    /// ASN.1 <c>OBJECT IDENTIFIER</c> (the PKCS#11 <i>namedCurve</i> choice). Returns a fresh copy on
    /// each call, so this is a method rather than a property.
    /// </summary>
    /// <exception cref="InvalidOperationException">The curve is the uninitialized <see langword="default"/>.</exception>
    public byte[] GetEcParams() => _ecParams is null
        ? throw new InvalidOperationException("The Pkcs11ECCurve is uninitialized (default); specify a curve.")
        : (byte[])_ecParams.Clone();

    /// <summary>
    /// Creates a named curve from a dotted-decimal OID value, with an optional friendly name and field
    /// size. Mirrors <see cref="ECCurve.CreateFromValue(string)"/>.
    /// </summary>
    /// <param name="oidValue">Dotted-decimal OID (e.g. <c>1.3.132.0.10</c>).</param>
    /// <param name="friendlyName">Optional human-readable name; resolved from <see cref="Pkcs11CurveCatalog.Default"/> when omitted.</param>
    /// <param name="fieldSizeBits">
    /// Optional field size in bits, for a curve outside <see cref="Pkcs11CurveCatalog.Default"/>;
    /// reported by <see cref="FieldSizeBits"/>. For a built-in curve it may be omitted, and must match
    /// when given.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="oidValue"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="oidValue"/> is not a valid OID, or <paramref name="fieldSizeBits"/> contradicts the
    /// built-in curve with that OID.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="fieldSizeBits"/> is not positive.</exception>
    public static Pkcs11ECCurve CreateFromValue(string oidValue, string? friendlyName = null, int? fieldSizeBits = null)
    {
        ArgumentNullException.ThrowIfNull(oidValue);
        if (fieldSizeBits is int bits)
        {
            if (bits <= 0)
                throw new ArgumentOutOfRangeException(nameof(fieldSizeBits), bits, "The field size must be positive.");
            if (Pkcs11CurveCatalog.Default.TryGetByOid(oidValue, out Pkcs11CurveInfo? builtIn) && builtIn.FieldSizeBits != bits)
                throw new ArgumentException(
                    $"{builtIn.Name} ({oidValue}) has a {builtIn.FieldSizeBits}-bit field, not {bits}.", nameof(fieldSizeBits));
        }

        return new Pkcs11ECCurve(oidValue, friendlyName ?? LookupName(oidValue), fieldSizeBits);
    }

    /// <summary>
    /// Creates a named curve from an <see cref="System.Security.Cryptography.Oid"/>. Mirrors
    /// <see cref="ECCurve.CreateFromOid(System.Security.Cryptography.Oid)"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="curveOid"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="curveOid"/> has no OID value.</exception>
    public static Pkcs11ECCurve CreateFromOid(Oid curveOid)
    {
        ArgumentNullException.ThrowIfNull(curveOid);
        if (curveOid.Value is null)
            throw new ArgumentException("The OID has no value.", nameof(curveOid));
        return new Pkcs11ECCurve(curveOid.Value, curveOid.FriendlyName ?? LookupName(curveOid.Value));
    }

    /// <summary>
    /// Creates a named curve from a friendly name (e.g. <c>nistP256</c>). Mirrors
    /// <see cref="ECCurve.CreateFromFriendlyName(string)"/>; resolves the OID
    /// from <see cref="Pkcs11CurveCatalog.Default"/>, falling back to the BCL's name resolution. For a
    /// curve of a custom catalog, use <see cref="Pkcs11CurveCatalog.TryGetByName"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="friendlyName"/> is null.</exception>
    /// <exception cref="ArgumentException">The name cannot be resolved to a curve OID.</exception>
    public static Pkcs11ECCurve CreateFromFriendlyName(string friendlyName)
    {
        ArgumentNullException.ThrowIfNull(friendlyName);
        if (Pkcs11CurveCatalog.Default.TryGetByName(friendlyName, out Pkcs11CurveInfo? info))
            return info.ToCurve();
        return FromECCurve(ECCurve.CreateFromFriendlyName(friendlyName));
    }

    /// <summary>
    /// Parses a <c>CKA_EC_PARAMS</c> value (a DER-encoded curve OID) back into a <see cref="Pkcs11ECCurve"/>.
    /// </summary>
    /// <exception cref="ArgumentException">The bytes are not a DER-encoded OID.</exception>
    public static Pkcs11ECCurve FromEcParams(ReadOnlySpan<byte> ecParams)
    {
        try
        {
            string oid = new AsnReader(ecParams.ToArray(), AsnEncodingRules.DER).ReadObjectIdentifier();
            return new Pkcs11ECCurve(oid, LookupName(oid));
        }
        catch (AsnContentException ex)
        {
            throw new ArgumentException("CKA_EC_PARAMS is not a DER-encoded named-curve OID.", nameof(ecParams), ex);
        }
    }

    /// <summary>Bridges to the BCL <see cref="ECCurve"/> (a named curve over the same OID).</summary>
    /// <exception cref="InvalidOperationException">The curve is the uninitialized <see langword="default"/>.</exception>
    public ECCurve ToECCurve()
    {
        if (Oid is null)
            throw new InvalidOperationException("The Pkcs11ECCurve is uninitialized (default); specify a curve.");
        return ECCurve.CreateFromValue(Oid);
    }

    /// <summary>Creates a <see cref="Pkcs11ECCurve"/> from a named BCL <see cref="ECCurve"/>.</summary>
    /// <exception cref="ArgumentException">The curve is not a named curve (has no OID).</exception>
    public static Pkcs11ECCurve FromECCurve(ECCurve curve)
    {
        if (!curve.IsNamed)
            throw new ArgumentException("Only named ECCurves (with an OID) can be converted.", nameof(curve));
        string? oid = curve.Oid.Value ?? throw new ArgumentException("The ECCurve has no OID value.", nameof(curve));
        return new Pkcs11ECCurve(oid, curve.Oid.FriendlyName);
    }

    /// <inheritdoc/>
    public bool Equals(Pkcs11ECCurve other) => string.Equals(Oid, other.Oid, StringComparison.Ordinal);
    /// <inheritdoc/>
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is Pkcs11ECCurve other && Equals(other);
    /// <inheritdoc/>
    public override int GetHashCode() => Oid?.GetHashCode(StringComparison.Ordinal) ?? 0;
    /// <summary>Indicates whether two curves have the same OID.</summary>
    public static bool operator ==(Pkcs11ECCurve left, Pkcs11ECCurve right) => left.Equals(right);
    /// <summary>Indicates whether two curves have different OIDs.</summary>
    public static bool operator !=(Pkcs11ECCurve left, Pkcs11ECCurve right) => !left.Equals(right);
    /// <inheritdoc/>
    public override string ToString() => FriendlyName is null ? (Oid ?? "<default>") : $"{FriendlyName} ({Oid})";

    /// <summary>Creates the curve a catalog entry describes, with its name and field size.</summary>
    internal static Pkcs11ECCurve FromInfo(Pkcs11CurveInfo info) => new(info.Oid, info.Name, info.FieldSizeBits);

    private static string? LookupName(string oid)
        => Pkcs11CurveCatalog.Default.TryGetByOid(oid, out Pkcs11CurveInfo? info) ? info.Name : null;
}
