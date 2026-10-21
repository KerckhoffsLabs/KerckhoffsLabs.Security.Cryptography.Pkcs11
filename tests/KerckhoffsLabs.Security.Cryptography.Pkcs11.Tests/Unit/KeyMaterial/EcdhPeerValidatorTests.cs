using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.KeyMaterial;

/// <summary>
/// Drives <see cref="EcdhPeerValidator"/> directly over a key whose <c>CKA_EC_PARAMS</c> and
/// <c>CKA_EC_POINT</c> answers are fixed, one check at a time. The adapter-level tests in
/// <c>ECDiffieHellmanPkcs11Tests_Managed</c> pass a peer that more than one check refuses; each peer
/// here is refused by exactly one check, and the assertion names it, so no check can go missing behind
/// another.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class EcdhPeerValidatorTests
{
    private const string Operation = "TestDerive";
    private const string PeerParam = "otherPartyPublicKey";

    // prime239v1 (X9.62): outside the curve catalog, so the field size cannot come from it.
    private const string Prime239v1Oid = "1.2.840.10045.3.1.4";

    public static bool BrainpoolP256r1Supported { get; } = ProbeCurve(BclECCurve.NamedCurves.brainpoolP256r1);

    public static bool Prime239v1Supported { get; } = ProbeCurve(BclECCurve.CreateFromValue(Prime239v1Oid));

    private static bool ProbeCurve(BclECCurve curve)
    {
        try
        {
            using (ECDiffieHellman.Create(curve)) { }
            return true;
        }
        catch (PlatformNotSupportedException) { return false; }
        catch (CryptographicException) { return false; }
    }

    // A local EC key on `curve` whose CKA_EC_POINT, when asked for, is unavailable.
    private static FakeKey LocalKey(Pkcs11ECCurve curve) => FakeKeys.Create(CKK.CKK_EC, type => type switch
    {
        CKA.CKA_EC_PARAMS => (CKR.CKR_OK, curve.GetEcParams()),
        _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
    });

    private static ECParameters PeerOn(BclECCurve curve)
    {
        using var peer = ECDiffieHellman.Create(curve);
        return peer.ExportParameters(includePrivateParameters: false);
    }

    private static ValidatedEcdhPeer Validate(Pkcs11Key localKey, ECParameters peer)
        => EcdhPeerValidator.Validate(localKey, peer, PeerParam, Operation);

    [Fact]
    public void PeerOnTheLocalCurve_IsValidatedAndEncoded()
    {
        using FakeKey local = LocalKey(Pkcs11ECCurve.NamedCurves.NistP256);
        ECParameters peer = PeerOn(BclECCurve.NamedCurves.nistP256);

        ValidatedEcdhPeer validated = Validate(local, peer);

        Assert.Equal(32, validated.FieldSizeBytes);
        Assert.Equal(peer.Q.X, validated.X);
        Assert.Equal(peer.Q.Y, validated.Y);
        Assert.Equal(EcPointEncoding.Encode(peer.Q.X!, peer.Q.Y!), validated.EncodedPoint);
    }

    // Same 32-byte field size and a valid point on its own curve: only the curve check refuses it, and
    // without it the token would agree with a point from a curve the local key is not on.
    [Fact(SkipUnless = nameof(BrainpoolP256r1Supported), Skip = "Requires " + nameof(BrainpoolP256r1Supported))]
    public void PeerOnAnotherCurveOfTheSameSize_IsRefusedByTheCurveCheck()
    {
        using FakeKey local = LocalKey(Pkcs11ECCurve.NamedCurves.NistP256);

        var ex = Assert.Throws<Pkcs11ArgumentException>(() => Validate(local, PeerOn(BclECCurve.NamedCurves.brainpoolP256r1)));

        Assert.Equal(CKR.CKR_ARGUMENTS_BAD, ex.ReturnValue);
        Assert.Equal($"{Operation} (peer public key is on curve brainpoolP256r1, expected nistP256)", ex.Method);
    }

    // Explicit parameters carry no OID, so they can never match a named local curve. The curve is
    // set by hand: macOS cannot export explicit parameters, and only the missing OID matters here.
    [Fact]
    public void PeerWithExplicitCurveParameters_IsRefusedByTheCurveCheck()
    {
        using FakeKey local = LocalKey(Pkcs11ECCurve.NamedCurves.NistP256);
        ECParameters explicitPeer = PeerOn(BclECCurve.NamedCurves.nistP256);
        explicitPeer.Curve = new BclECCurve { CurveType = BclECCurve.ECCurveType.PrimeShortWeierstrass };

        var ex = Assert.Throws<Pkcs11ArgumentException>(() => Validate(local, explicitPeer));

        Assert.Equal($"{Operation} (peer public key is on curve unknown, expected nistP256)", ex.Method);
    }

    [Fact]
    public void PeerYOfTheWrongLength_IsRefusedByTheLengthCheck()
    {
        using FakeKey local = LocalKey(Pkcs11ECCurve.NamedCurves.NistP256);
        ECParameters peer = PeerOn(BclECCurve.NamedCurves.nistP256);
        peer.Q.Y = peer.Q.Y![1..];

        var ex = Assert.Throws<Pkcs11ArgumentException>(() => Validate(local, peer));

        Assert.Equal($"{Operation} (peer coordinate length 32/31 bytes does not match the curve's 32-byte field size)", ex.Method);
    }

    [Fact]
    public void OffCurvePoint_IsRefusedByThePointCheck()
    {
        using FakeKey local = LocalKey(Pkcs11ECCurve.NamedCurves.NistP256);
        ECParameters peer = PeerOn(BclECCurve.NamedCurves.nistP256);
        peer.Q.Y![^1] ^= 1;

        var ex = Assert.Throws<Pkcs11ArgumentException>(() => Validate(local, peer));

        Assert.Equal($"{Operation} (peer public key point does not satisfy the curve equation)", ex.Method);
    }

    [Fact]
    public void PeerWithoutACoordinate_IsRefusedAsAnArgument()
    {
        using FakeKey local = LocalKey(Pkcs11ECCurve.NamedCurves.NistP256);
        ECParameters noX = PeerOn(BclECCurve.NamedCurves.nistP256);
        noX.Q.X = null;
        ECParameters noY = PeerOn(BclECCurve.NamedCurves.nistP256);
        noY.Q.Y = null;

        var missingX = Assert.Throws<ArgumentException>(() => Validate(local, noX));
        var missingY = Assert.Throws<ArgumentException>(() => Validate(local, noY));

        Assert.Equal(PeerParam, missingX.ParamName);
        Assert.StartsWith("Peer public key has no X coordinate.", missingX.Message, StringComparison.Ordinal);
        Assert.Equal(PeerParam, missingY.ParamName);
        Assert.StartsWith("Peer public key has no Y coordinate.", missingY.Message, StringComparison.Ordinal);
    }

    // Without the local curve there is nothing to hold the peer to: refuse rather than skip the check.
    [Fact]
    public void LocalEcParamsUnreadable_IsRefused()
    {
        using FakeKey local = FakeKeys.Create(CKK.CKK_EC, _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null));

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => Validate(local, PeerOn(BclECCurve.NamedCurves.nistP256)));

        Assert.Equal(CKR.CKR_ATTRIBUTE_SENSITIVE, ex.ReturnValue);
        Assert.Equal($"{Operation} (local CKA_EC_PARAMS not readable — cannot validate the peer's curve)", ex.Method);
    }

    // A curve outside the catalog on a token that hides CKA_EC_POINT: the peer's X is the last resort.
    [Fact(SkipUnless = nameof(Prime239v1Supported), Skip = "Requires " + nameof(Prime239v1Supported))]
    public void CurveOutsideTheCatalog_WithoutALocalPoint_TakesTheFieldSizeFromThePeer()
    {
        using FakeKey local = LocalKey(Pkcs11ECCurve.CreateFromValue(Prime239v1Oid, "prime239v1"));

        ValidatedEcdhPeer validated = Validate(local, PeerOn(BclECCurve.CreateFromValue(Prime239v1Oid)));

        Assert.Equal(30, validated.FieldSizeBytes);
    }
}
