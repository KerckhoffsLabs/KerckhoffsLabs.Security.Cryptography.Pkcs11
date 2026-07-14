using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// Covers the ECCurve value type: CKA_EC_PARAMS (DER OID) encoding/round-trip, the BCL bridge, the
// named-curve catalog, and equality. No token needed — this only manipulates curve metadata.
public sealed class ECCurveTests
{
    [Fact]
    public void EcParams_MatchIndependentDerVectors()
    {
        // TestKeys holds hand-encoded DER OIDs — an oracle independent of ECCurve's AsnWriter path,
        // so this pins the encoding for every NIST prime (e.g. P-256 = 06 08 2A 86 48 CE 3D 03 01 07).
        Assert.Equal(TestKeys.EcP256Oid, ECCurve.NamedCurves.NistP256.GetEcParams());
        Assert.Equal(TestKeys.EcP384Oid, ECCurve.NamedCurves.NistP384.GetEcParams());
        Assert.Equal(TestKeys.EcP521Oid, ECCurve.NamedCurves.NistP521.GetEcParams());
    }

    [Fact]
    public void NamedCurve_HasOid_FriendlyName_And_NamedCurveType()
    {
        ECCurve curve = ECCurve.NamedCurves.NistP384;
        Assert.Equal("1.3.132.0.34", curve.Oid);
        Assert.Equal("nistP384", curve.FriendlyName);
        Assert.True(curve.IsNamed);
        Assert.False(curve.IsDefault);
        Assert.Equal(ECCurve.ECCurveType.Named, curve.CurveType);
    }

    [Fact]
    public void FromEcParams_RoundTrips_OidAndName()
    {
        ECCurve original = ECCurve.NamedCurves.BrainpoolP256r1;
        ECCurve parsed = ECCurve.FromEcParams(original.GetEcParams());

        Assert.Equal(original.Oid, parsed.Oid);
        Assert.Equal("brainpoolP256r1", parsed.FriendlyName);
        Assert.Equal(original, parsed);
    }

    [Fact]
    public void CreateFromValue_ResolvesKnownName_AndHonorsExplicitName()
    {
        Assert.Equal("secp256k1", ECCurve.CreateFromValue("1.3.132.0.10").FriendlyName);
        Assert.Equal("my-curve", ECCurve.CreateFromValue("1.2.3.4", "my-curve").FriendlyName);
    }

    [Fact]
    public void CreateFromValue_UnknownOid_HasNullName_ButValidEcParams()
    {
        ECCurve curve = ECCurve.CreateFromValue("1.2.3.4");
        Assert.Null(curve.FriendlyName);
        // Still encodes a valid DER OID, so a token could be asked for an unlisted curve.
        Assert.Equal(curve, ECCurve.FromEcParams(curve.GetEcParams()));
    }

    [Fact]
    public void CreateFromValue_NullOid_Throws() =>
        Assert.Throws<ArgumentNullException>(() => ECCurve.CreateFromValue(null!));

    [Fact]
    public void FromEcParams_NonOidBytes_Throws() =>
        Assert.Throws<ArgumentException>(() => ECCurve.FromEcParams([0x01, 0x02, 0x03]));

    [Fact]
    public void CreateFromFriendlyName_ResolvesOid()
    {
        ECCurve curve = ECCurve.CreateFromFriendlyName("nistP521");
        Assert.Equal("1.3.132.0.35", curve.Oid);
    }

    [Fact]
    public void ToECCurve_BridgesToNamedBclCurve_WithSameOid()
    {
        BclECCurve bcl = ECCurve.NamedCurves.NistP256.ToECCurve();
        Assert.True(bcl.IsNamed);
        Assert.Equal("1.2.840.10045.3.1.7", bcl.Oid.Value);
    }

    [Fact]
    public void FromECCurve_RoundTripsThroughBcl()
    {
        ECCurve roundTripped = ECCurve.FromECCurve(BclECCurve.NamedCurves.nistP256);
        Assert.Equal(ECCurve.NamedCurves.NistP256, roundTripped);
    }

    [Fact]
    public void FromECCurve_ExplicitCurve_Throws()
    {
        // An explicit curve has no OID and cannot be represented by a PKCS#11 namedCurve.
        BclECCurve explicitCurve = default;
        explicitCurve.CurveType = BclECCurve.ECCurveType.PrimeShortWeierstrass;
        Assert.Throws<ArgumentException>(() => ECCurve.FromECCurve(explicitCurve));
    }

    [Fact]
    public void Default_IsUninitialized_AndEcParamsThrows()
    {
        ECCurve def = default;
        Assert.True(def.IsDefault);
        Assert.False(def.IsNamed);
        Assert.Equal(ECCurve.ECCurveType.Implicit, def.CurveType);
        Assert.Null(def.Oid);
        Assert.Throws<InvalidOperationException>(() => def.GetEcParams());
    }

    [Fact]
    public void Equality_IsByOid()
    {
        ECCurve a = ECCurve.CreateFromValue("1.2.840.10045.3.1.7");
        ECCurve b = ECCurve.NamedCurves.NistP256;
        Assert.True(a == b);
        Assert.False(a != b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.True(ECCurve.NamedCurves.NistP256 != ECCurve.NamedCurves.NistP384);
    }

    [Fact]
    public void CreateFromOid_HonorsValueAndExplicitName()
    {
        ECCurve curve = ECCurve.CreateFromOid(new Oid("1.2.3.4", "explicit"));
        Assert.Equal("1.2.3.4", curve.Oid);
        Assert.Equal("explicit", curve.FriendlyName);
    }

    [Fact]
    public void CreateFromOid_NullOrValueless_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => ECCurve.CreateFromOid(null!));
        Assert.Throws<ArgumentException>(() => ECCurve.CreateFromOid(new Oid()));
    }

    [Fact]
    public void CreateFromFriendlyName_Null_Throws() =>
        Assert.Throws<ArgumentNullException>(() => ECCurve.CreateFromFriendlyName(null!));

    [Fact]
    public void EcParams_ReturnsIndependentCopy()
    {
        ECCurve curve = ECCurve.NamedCurves.NistP256;

        byte[] first = curve.GetEcParams();
        first[0] = 0xFF; // a caller mutating the returned buffer must not corrupt the curve
        Assert.Equal(TestKeys.EcP256Oid, curve.GetEcParams());
        Assert.NotSame(curve.GetEcParams(), curve.GetEcParams()); // a fresh array each call
    }

    [Fact]
    public void ToString_RendersNameOidOrDefault()
    {
        Assert.Equal("nistP256 (1.2.840.10045.3.1.7)", ECCurve.NamedCurves.NistP256.ToString());
        Assert.Equal("1.2.3.4", ECCurve.CreateFromValue("1.2.3.4").ToString()); // unknown OID, no name
        Assert.Equal("<default>", default(ECCurve).ToString());
    }

    [Fact]
    public void Equals_Object_DistinguishesTypeAndNull()
    {
        ECCurve p256 = ECCurve.NamedCurves.NistP256;
        Assert.True(p256.Equals((object)ECCurve.CreateFromValue("1.2.840.10045.3.1.7")));
        Assert.False(p256.Equals("not a curve"));
        Assert.False(p256.Equals(null));
        Assert.Equal(0, default(ECCurve).GetHashCode());
    }

    [Fact]
    public void IsBelowSecurityBaseline_FlagsSub128BitCurves()
    {
#pragma warning disable KLPKCS11007 // deliberately referencing the obsolete sub-128-bit curves
        ECCurve[] weak =
        [
            ECCurve.NamedCurves.NistP192, ECCurve.NamedCurves.NistP224,
            ECCurve.NamedCurves.BrainpoolP160r1, ECCurve.NamedCurves.BrainpoolP160t1,
            ECCurve.NamedCurves.BrainpoolP192r1, ECCurve.NamedCurves.BrainpoolP192t1,
            ECCurve.NamedCurves.BrainpoolP224r1, ECCurve.NamedCurves.BrainpoolP224t1,
            ECCurve.NamedCurves.Secp192k1, ECCurve.NamedCurves.Secp224k1,
        ];
#pragma warning restore KLPKCS11007
        Assert.All(weak, c => Assert.True(c.IsBelowSecurityBaseline, $"{c} should be sub-baseline"));

        ECCurve[] strong =
        [
            ECCurve.NamedCurves.NistP256, ECCurve.NamedCurves.NistP384, ECCurve.NamedCurves.NistP521,
            ECCurve.NamedCurves.Secp256k1, ECCurve.NamedCurves.BrainpoolP256r1,
            ECCurve.NamedCurves.BrainpoolP512t1, ECCurve.NamedCurves.Sm2,
        ];
        Assert.All(strong, c => Assert.False(c.IsBelowSecurityBaseline, $"{c} should meet baseline"));

        // An OID outside the catalog can't be classified from the OID alone -> not flagged.
        Assert.False(ECCurve.CreateFromValue("1.2.3.4").IsBelowSecurityBaseline);
    }

    [Fact]
    public void NamedCurves_Catalog_OidsNamesAndEncodingAreConsistent()
    {
        // Every entry pairs the NamedCurves property with an independently written OID + name, so a
        // typo in any catalog OID (e.g. a swapped Brainpool r1/t1 index) fails here. Covers all of
        // the PKCS#11 v3.2 prime-field named curves. The sub-128-bit curves are intentionally
        // [Obsolete]; this catalog test references them on purpose.
#pragma warning disable KLPKCS11007
        (ECCurve curve, string oid, string name)[] catalog =
        [
            (ECCurve.NamedCurves.NistP192, "1.2.840.10045.3.1.1", "nistP192"),
            (ECCurve.NamedCurves.NistP224, "1.3.132.0.33", "nistP224"),
            (ECCurve.NamedCurves.NistP256, "1.2.840.10045.3.1.7", "nistP256"),
            (ECCurve.NamedCurves.NistP384, "1.3.132.0.34", "nistP384"),
            (ECCurve.NamedCurves.NistP521, "1.3.132.0.35", "nistP521"),
            (ECCurve.NamedCurves.Secp192k1, "1.3.132.0.31", "secp192k1"),
            (ECCurve.NamedCurves.Secp224k1, "1.3.132.0.32", "secp224k1"),
            (ECCurve.NamedCurves.Secp256k1, "1.3.132.0.10", "secp256k1"),
            (ECCurve.NamedCurves.BrainpoolP160r1, "1.3.36.3.3.2.8.1.1.1", "brainpoolP160r1"),
            (ECCurve.NamedCurves.BrainpoolP160t1, "1.3.36.3.3.2.8.1.1.2", "brainpoolP160t1"),
            (ECCurve.NamedCurves.BrainpoolP192r1, "1.3.36.3.3.2.8.1.1.3", "brainpoolP192r1"),
            (ECCurve.NamedCurves.BrainpoolP192t1, "1.3.36.3.3.2.8.1.1.4", "brainpoolP192t1"),
            (ECCurve.NamedCurves.BrainpoolP224r1, "1.3.36.3.3.2.8.1.1.5", "brainpoolP224r1"),
            (ECCurve.NamedCurves.BrainpoolP224t1, "1.3.36.3.3.2.8.1.1.6", "brainpoolP224t1"),
            (ECCurve.NamedCurves.BrainpoolP256r1, "1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1"),
            (ECCurve.NamedCurves.BrainpoolP256t1, "1.3.36.3.3.2.8.1.1.8", "brainpoolP256t1"),
            (ECCurve.NamedCurves.BrainpoolP320r1, "1.3.36.3.3.2.8.1.1.9", "brainpoolP320r1"),
            (ECCurve.NamedCurves.BrainpoolP320t1, "1.3.36.3.3.2.8.1.1.10", "brainpoolP320t1"),
            (ECCurve.NamedCurves.BrainpoolP384r1, "1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1"),
            (ECCurve.NamedCurves.BrainpoolP384t1, "1.3.36.3.3.2.8.1.1.12", "brainpoolP384t1"),
            (ECCurve.NamedCurves.BrainpoolP512r1, "1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1"),
            (ECCurve.NamedCurves.BrainpoolP512t1, "1.3.36.3.3.2.8.1.1.14", "brainpoolP512t1"),
            (ECCurve.NamedCurves.Sm2, "1.2.156.10197.1.301", "sm2"),
        ];
#pragma warning restore KLPKCS11007

        Assert.Equal(23, catalog.Length);
        foreach (var (curve, oid, name) in catalog)
        {
            Assert.Equal(oid, curve.Oid);
            Assert.Equal(name, curve.FriendlyName);
            Assert.Equal(ECCurve.ECCurveType.Named, curve.CurveType);
            Assert.Equal(curve, ECCurve.CreateFromValue(oid));          // property == factory
            Assert.Equal(curve, ECCurve.FromEcParams(curve.GetEcParams()));  // CKA_EC_PARAMS round-trip
        }
    }
}
