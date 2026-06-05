using System.Formats.Asn1;
using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Identifies a named elliptic curve by its object identifier (OID), mirroring the shape of the BCL
/// <see cref="System.Security.Cryptography.ECCurve"/>. A PKCS#11 EC key pair selects its curve through
/// the <c>CKA_EC_PARAMS</c> attribute, which for a named curve is the DER-encoded curve OID — exposed
/// here as <see cref="EcParams"/>.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="NamedCurves"/> nested class provides the prime-field (Weierstrass) curves a PKCS#11
/// v3.2 token may implement via <c>CKM_EC_KEY_PAIR_GEN</c> — the NIST primes, the Koblitz curves
/// (secp192k1/secp224k1/secp256k1), the Brainpool family (RFC 5639), and SM2. Any other curve can be selected with
/// <see cref="CreateFromValue(string, string?)"/>. Twisted-Edwards (Ed25519/Ed448) and Montgomery
/// (X25519/X448) curves use different key types and key-pair-gen mechanisms and are intentionally
/// outside this type.
/// </para>
/// <para>This is a value type; the uninitialized <c>default</c> has no OID and throws from
/// <see cref="EcParams"/>.</para>
/// </remarks>
public readonly partial struct ECCurve : IEquatable<ECCurve>
{
    private readonly byte[]? _ecParams;

    private ECCurve(string oid, string? friendlyName)
    {
        Oid = oid;
        FriendlyName = friendlyName;
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
    /// <see cref="ECCurveType.Named"/>; the uninitialized <c>default</c> reports
    /// <see cref="ECCurveType.Implicit"/>.
    /// </summary>
    public ECCurveType CurveType => Oid is null ? ECCurveType.Implicit : ECCurveType.Named;

    /// <summary>True when this instance names a curve (the only kind PKCS#11 selects by OID).</summary>
    public bool IsNamed => CurveType == ECCurveType.Named;

    /// <summary>True for the uninitialized <c>default(ECCurve)</c>, which carries no OID.</summary>
    public bool IsDefault => Oid is null;

    /// <summary>
    /// True when this is a known catalog curve providing less than 128-bit security (field size
    /// &lt; 256-bit): the 160/192/224-bit NIST and Brainpool curves.
    /// <see cref="Pkcs11Workspace.GenerateEcKeyPair"/> refuses these unless
    /// <see cref="Pkcs11Workspace.AllowInsecure"/> is set. An OID outside the catalog reports
    /// <see langword="false"/> — its strength can't be inferred from the OID alone.
    /// </summary>
    internal bool IsBelowSecurityBaseline => Oid is not null && s_belowBaselineOids.Contains(Oid);

    /// <summary>
    /// The <c>CKA_EC_PARAMS</c> value for this curve: the DER encoding of the curve OID as an ASN.1
    /// <c>OBJECT IDENTIFIER</c> (the PKCS#11 <i>namedCurve</i> choice). Returns a fresh copy.
    /// </summary>
    /// <exception cref="InvalidOperationException">The curve is the uninitialized <c>default</c>.</exception>
    public byte[] EcParams => _ecParams is null
        ? throw new InvalidOperationException("The ECCurve is uninitialized (default); specify a curve.")
        : (byte[])_ecParams.Clone();

    /// <summary>
    /// Creates a named curve from a dotted-decimal OID value, with an optional friendly name. Mirrors
    /// <see cref="System.Security.Cryptography.ECCurve.CreateFromValue(string)"/>.
    /// </summary>
    /// <param name="oidValue">Dotted-decimal OID (e.g. <c>1.3.132.0.10</c>).</param>
    /// <param name="friendlyName">Optional human-readable name; resolved from the known set when omitted.</param>
    /// <exception cref="ArgumentNullException"><paramref name="oidValue"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="oidValue"/> is not a valid OID.</exception>
    public static ECCurve CreateFromValue(string oidValue, string? friendlyName = null)
    {
        ArgumentNullException.ThrowIfNull(oidValue);
        return new ECCurve(oidValue, friendlyName ?? LookupName(oidValue));
    }

    /// <summary>
    /// Creates a named curve from an <see cref="System.Security.Cryptography.Oid"/>. Mirrors
    /// <see cref="System.Security.Cryptography.ECCurve.CreateFromOid(System.Security.Cryptography.Oid)"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="curveOid"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="curveOid"/> has no OID value.</exception>
    public static ECCurve CreateFromOid(Oid curveOid)
    {
        ArgumentNullException.ThrowIfNull(curveOid);
        if (curveOid.Value is null)
            throw new ArgumentException("The OID has no value.", nameof(curveOid));
        return new ECCurve(curveOid.Value, curveOid.FriendlyName ?? LookupName(curveOid.Value));
    }

    /// <summary>
    /// Creates a named curve from a friendly name (e.g. <c>nistP256</c>). Mirrors
    /// <see cref="System.Security.Cryptography.ECCurve.CreateFromFriendlyName(string)"/>; resolves the OID
    /// from the known set, falling back to the BCL's name resolution.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="friendlyName"/> is null.</exception>
    /// <exception cref="ArgumentException">The name cannot be resolved to a curve OID.</exception>
    public static ECCurve CreateFromFriendlyName(string friendlyName)
    {
        ArgumentNullException.ThrowIfNull(friendlyName);
        if (s_oidsByName.TryGetValue(friendlyName, out var oid))
            return new ECCurve(oid, friendlyName);
        return FromECCurve(BclECCurve.CreateFromFriendlyName(friendlyName));
    }

    /// <summary>
    /// Parses a <c>CKA_EC_PARAMS</c> value (a DER-encoded curve OID) back into an <see cref="ECCurve"/>.
    /// </summary>
    /// <exception cref="ArgumentException">The bytes are not a DER-encoded OID.</exception>
    public static ECCurve FromEcParams(ReadOnlySpan<byte> ecParams)
    {
        try
        {
            string oid = new AsnReader(ecParams.ToArray(), AsnEncodingRules.DER).ReadObjectIdentifier();
            return new ECCurve(oid, LookupName(oid));
        }
        catch (AsnContentException ex)
        {
            throw new ArgumentException("CKA_EC_PARAMS is not a DER-encoded named-curve OID.", nameof(ecParams), ex);
        }
    }

    /// <summary>Bridges to the BCL <see cref="System.Security.Cryptography.ECCurve"/> (a named curve over the same OID).</summary>
    /// <exception cref="InvalidOperationException">The curve is the uninitialized <c>default</c>.</exception>
    public BclECCurve ToECCurve()
    {
        if (Oid is null)
            throw new InvalidOperationException("The ECCurve is uninitialized (default); specify a curve.");
        return BclECCurve.CreateFromValue(Oid);
    }

    /// <summary>Creates an <see cref="ECCurve"/> from a named BCL <see cref="System.Security.Cryptography.ECCurve"/>.</summary>
    /// <exception cref="ArgumentException">The curve is not a named curve (has no OID).</exception>
    public static ECCurve FromECCurve(BclECCurve curve)
    {
        if (!curve.IsNamed)
            throw new ArgumentException("Only named ECCurves (with an OID) can be converted.", nameof(curve));
        string? oid = curve.Oid.Value;
        if (oid is null)
            throw new ArgumentException("The ECCurve has no OID value.", nameof(curve));
        return new ECCurve(oid, curve.Oid.FriendlyName);
    }

    /// <inheritdoc/>
    public bool Equals(ECCurve other) => string.Equals(Oid, other.Oid, StringComparison.Ordinal);
    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is ECCurve other && Equals(other);
    /// <inheritdoc/>
    public override int GetHashCode() => Oid?.GetHashCode(StringComparison.Ordinal) ?? 0;
    /// <summary>Indicates whether two curves have the same OID.</summary>
    public static bool operator ==(ECCurve left, ECCurve right) => left.Equals(right);
    /// <summary>Indicates whether two curves have different OIDs.</summary>
    public static bool operator !=(ECCurve left, ECCurve right) => !left.Equals(right);
    /// <inheritdoc/>
    public override string ToString() => FriendlyName is null ? (Oid ?? "<default>") : $"{FriendlyName} ({Oid})";

    private static string? LookupName(string oid) => s_namesByOid.TryGetValue(oid, out var n) ? n : null;
}
