using BclECCurve = System.Security.Cryptography.ECCurve;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// Covers the ECCurve value type: CKA_EC_PARAMS (DER OID) encoding/round-trip, the BCL bridge, the
// named-curve catalog, and equality. No token needed — this only manipulates curve metadata.
public sealed class ECCurveTests
{
    [Fact]
    public void NistP256_EcParams_IsDerEncodedCurveOid()
    {
        // OBJECT IDENTIFIER 1.2.840.10045.3.1.7 (prime256v1) = 06 08 2A 86 48 CE 3D 03 01 07.
        byte[] expected = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        Assert.Equal(expected, ECCurve.NamedCurves.NistP256.EcParams);
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
        ECCurve parsed = ECCurve.FromEcParams(original.EcParams);

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
        Assert.Equal(curve, ECCurve.FromEcParams(curve.EcParams));
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
        Assert.Throws<InvalidOperationException>(() => def.EcParams);
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

    public static TheoryData<string, string> AllNamedCurves => new()
    {
        { "1.2.840.10045.3.1.1", "nistP192" },
        { "1.3.132.0.33", "nistP224" },
        { "1.2.840.10045.3.1.7", "nistP256" },
        { "1.3.132.0.34", "nistP384" },
        { "1.3.132.0.35", "nistP521" },
        { "1.3.132.0.10", "secp256k1" },
        { "1.3.36.3.3.2.8.1.1.1", "brainpoolP160r1" },
        { "1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1" },
        { "1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1" },
        { "1.2.156.10197.1.301", "sm2" },
    };

    [Theory]
    [MemberData(nameof(AllNamedCurves))]
    public void NamedCurves_EncodeAndParseConsistently(string oid, string name)
    {
        ECCurve curve = ECCurve.CreateFromValue(oid);
        Assert.Equal(name, curve.FriendlyName);

        ECCurve parsed = ECCurve.FromEcParams(curve.EcParams);
        Assert.Equal(oid, parsed.Oid);
        Assert.Equal(name, parsed.FriendlyName);
    }
}
