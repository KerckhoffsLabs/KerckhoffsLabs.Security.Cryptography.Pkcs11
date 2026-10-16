using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The EC members of <see cref="Pkcs11Key"/> over the in-process <c>ManagedSoftToken</c>:
/// <see cref="Pkcs11Key.GetCurve"/>, <see cref="Pkcs11Key.ExportEcPublicKey"/> and
/// <see cref="Pkcs11Key.DeriveRawSecretEcdh"/>, each cross-checked against the BCL. The adapters
/// (<c>ECDsaPkcs11</c>, <c>ECDiffieHellmanPkcs11</c>) are built on these, and their own tests cover
/// the same behaviour through the BCL surface.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11KeyEllipticCurveTests
{
    public static bool Supported { get; } = Probe();

    private static bool Probe()
    {
        try
        {
            using (ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256)) { }
            using (ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP384)) { }
            return true;
        }
        catch (PlatformNotSupportedException) { return false; }
        catch (CryptographicException) { return false; }
    }

    private static void WithEcKey(Pkcs11ECCurve curve, Action<Pkcs11Key> body, bool allowExtraction = false)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using IDisposable? insecure = allowExtraction ? session.UsePolicy(CryptoPolicy.AllowInsecure) : null;
        using var key = session.GenerateEcKeyPair(curve);
        body(key);
    }

    private static void WithAesKey(Action<Pkcs11Key> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var key = session.GenerateAesKey();
        body(key);
    }

    // === GetCurve ============================================================

    [Theory(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    [InlineData("1.2.840.10045.3.1.7", "nistP256", 256)]
    [InlineData("1.3.132.0.34", "nistP384", 384)]
    public void GetCurve_IsTheGeneratedCurve_ResolvedThroughTheCatalog(string oid, string name, int fieldSizeBits)
        => WithEcKey(Pkcs11ECCurve.CreateFromValue(oid), key =>
        {
            Pkcs11ECCurve curve = key.GetCurve();

            Assert.Equal(oid, curve.Oid);
            Assert.Equal(name, curve.FriendlyName);
            Assert.Equal(fieldSizeBits, curve.FieldSizeBits);
        });

    [Fact]
    public void GetCurve_NonEcKey_Throws() => WithAesKey(key =>
        Assert.Throws<InvalidOperationException>(() => key.GetCurve()));

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void GetCurve_DisposedKey_Throws() => WithEcKey(Pkcs11ECCurve.NamedCurves.NistP256, key =>
    {
        key.Dispose();
        Assert.Throws<ObjectDisposedException>(() => key.GetCurve());
    });

    // === ExportEcPublicKey ===================================================

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void ExportEcPublicKey_IsTheTokenPoint_WithoutPrivateParameters() => WithEcKey(Pkcs11ECCurve.NamedCurves.NistP256, key =>
    {
        ECParameters exported = key.ExportEcPublicKey();

        Assert.Null(exported.D);
        Assert.Equal("1.2.840.10045.3.1.7", exported.Curve.Oid.Value);
        Assert.Equal(32, exported.Q.X!.Length);
        Assert.Equal(32, exported.Q.Y!.Length);

        // The BCL accepts it, which also checks the point is on the curve.
        using var bcl = ECDiffieHellman.Create(exported);
        Assert.Equal(256, bcl.KeySize);
    });

    [Fact]
    public void ExportEcPublicKey_NonEcKey_Throws() => WithAesKey(key =>
        Assert.Throws<InvalidOperationException>(() => key.ExportEcPublicKey()));

    // === DeriveRawSecretEcdh =================================================

    [Theory(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    [InlineData("1.2.840.10045.3.1.7", 32)]
    [InlineData("1.3.132.0.34", 48)]
    public void DeriveRawSecretEcdh_MatchesBcl(string oid, int fieldSizeBytes)
        => WithEcKey(Pkcs11ECCurve.CreateFromValue(oid), alice =>
        {
            using var bob = ECDiffieHellman.Create(BclECCurve.CreateFromValue(oid));
            using var alicePublic = ECDiffieHellman.Create(alice.ExportEcPublicKey());

            byte[] aliceZ = alice.DeriveRawSecretEcdh(bob.ExportParameters(includePrivateParameters: false));
            byte[] bobZ = bob.DeriveRawSecretAgreement(alicePublic.PublicKey);

            Assert.Equal(fieldSizeBytes, aliceZ.Length);
            Assert.Equal(bobZ, aliceZ);
        }, allowExtraction: true);

    // The export check runs before the peer is even looked at: an invalid peer still gets the policy
    // refusal, so a strict session learns nothing about the peer from the error.
    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecretEcdh_DefaultPolicy_IsRefusedBeforeValidation() => WithEcKey(Pkcs11ECCurve.NamedCurves.NistP256, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP384);

        Assert.Throws<CryptoPolicyViolationException>(
            () => alice.DeriveRawSecretEcdh(bob.ExportParameters(includePrivateParameters: false)));
    });

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecretEcdh_PeerOnAnotherCurve_Throws() => WithEcKey(Pkcs11ECCurve.NamedCurves.NistP256, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP384);

        Assert.Throws<Pkcs11ArgumentException>(
            () => alice.DeriveRawSecretEcdh(bob.ExportParameters(includePrivateParameters: false)));
    }, allowExtraction: true);

    // A point off the curve is the invalid-curve attack's input; it must never reach C_DeriveKey.
    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecretEcdh_PointOffTheCurve_Throws() => WithEcKey(Pkcs11ECCurve.NamedCurves.NistP256, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        ECParameters peer = bob.ExportParameters(includePrivateParameters: false);
        peer.Q.Y![^1] ^= 1;

        Assert.Throws<Pkcs11ArgumentException>(() => alice.DeriveRawSecretEcdh(peer));
    }, allowExtraction: true);

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecretEcdh_PeerWithoutY_Throws() => WithEcKey(Pkcs11ECCurve.NamedCurves.NistP256, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        ECParameters peer = bob.ExportParameters(includePrivateParameters: false);
        peer.Q.Y = null;

        var ex = Assert.Throws<ArgumentException>(() => alice.DeriveRawSecretEcdh(peer));
        Assert.Equal("peerPublicKey", ex.ParamName);
    }, allowExtraction: true);

    [Fact]
    public void DeriveRawSecretEcdh_NonEcKey_Throws() => WithAesKey(key =>
        Assert.Throws<InvalidOperationException>(() => key.DeriveRawSecretEcdh(default)));
}
