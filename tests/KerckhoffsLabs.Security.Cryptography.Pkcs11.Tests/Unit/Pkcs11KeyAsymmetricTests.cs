using System.Formats.Asn1;
using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The key-type-neutral members of <see cref="Pkcs11Key"/> over the in-process <c>ManagedSoftToken</c>:
/// <see cref="Pkcs11Key.KeySize"/>, <see cref="Pkcs11Key.Export"/> and
/// <see cref="Pkcs11Key.DeriveRawSecret"/>, cross-checked against the BCL. The EC adapters are built on
/// them, and their own tests cover the same behaviour through the BCL surface.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11KeyAsymmetricTests
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

    private const string P256 = "1.2.840.10045.3.1.7";
    private const string P384 = "1.3.132.0.34";

    private static void WithKey(Func<Pkcs11Session, Pkcs11Key> generate, Action<Pkcs11Key> body, bool allowExtraction = false)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using IDisposable? insecure = allowExtraction ? session.UsePolicy(CryptoPolicy.AllowInsecure) : null;
        using var key = generate(session);
        body(key);
    }

    private static void WithEcKey(string oid, Action<Pkcs11Key> body, bool allowExtraction = false)
        => WithKey(s => s.GenerateEcKeyPair(Pkcs11ECCurve.CreateFromValue(oid)), body, allowExtraction);

    private static void WithAesKey(Action<Pkcs11Key> body) => WithKey(s => s.GenerateAesKey(256), body);

    // === KeySize ==============================================================

    [Theory(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    [InlineData(P256, 256)]
    [InlineData(P384, 384)]
    public void KeySize_EcKey_IsTheCurveFieldSize(string oid, int bits)
        => WithEcKey(oid, key => Assert.Equal(bits, key.KeySize));

    [Fact]
    public void KeySize_RsaKey_IsTheModulusSize()
        => WithKey(s => s.GenerateRsaSigningKeyPair(3072), key => Assert.Equal(3072, key.KeySize));

    [Fact]
    public void KeySize_SecretKey_IsTheValueLength() => WithAesKey(key => Assert.Equal(256, key.KeySize));

    [Fact]
    public void KeySize_DisposedKey_Throws() => WithAesKey(key =>
    {
        key.Dispose();
        Assert.Throws<ObjectDisposedException>(() => key.KeySize);
    });

    // === Export ===============================================================

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void Export_SubjectPublicKeyInfo_IsImportedByTheBcl() => WithEcKey(P256, key =>
    {
        byte[] spki = key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo);

        using var bcl = ECDiffieHellman.Create();
        bcl.ImportSubjectPublicKeyInfo(spki, out int read);
        Assert.Equal(spki.Length, read);
        ECParameters p = bcl.ExportParameters(includePrivateParameters: false);
        Assert.Equal(P256, p.Curve.Oid.Value);
        Assert.Equal(spki, bcl.ExportSubjectPublicKeyInfo());
    });

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void Export_RawPublicKey_IsTheUncompressedPointOfTheSpki() => WithEcKey(P256, key =>
    {
        byte[] raw = key.Export(Pkcs11KeyBlobFormat.RawPublicKey);
        using var bcl = ECDiffieHellman.Create();
        bcl.ImportSubjectPublicKeyInfo(key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo), out _);
        ECParameters p = bcl.ExportParameters(includePrivateParameters: false);

        Assert.Equal([0x04, .. p.Q.X!, .. p.Q.Y!], raw);
    });

    [Fact]
    public void Export_SecretKey_IsNotSupported() => WithAesKey(key =>
        Assert.Throws<NotSupportedException>(() => key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo)));

    [Fact]
    public void Export_UndefinedFormat_Throws() => WithAesKey(key =>
        Assert.Throws<ArgumentOutOfRangeException>(() => key.Export((Pkcs11KeyBlobFormat)42)));

    // === DeriveRawSecret ======================================================

    [Theory(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    [InlineData(P256, 32)]
    [InlineData(P384, 48)]
    public void DeriveRawSecret_MatchesBcl(string oid, int fieldSizeBytes) => WithEcKey(oid, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.CreateFromValue(oid));
        using var alicePublic = ECDiffieHellman.Create();
        alicePublic.ImportSubjectPublicKeyInfo(alice.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo), out _);

        byte[] aliceZ = alice.DeriveRawSecret(bob.ExportSubjectPublicKeyInfo());
        byte[] bobZ = bob.DeriveRawSecretAgreement(alicePublic.PublicKey);

        Assert.Equal(fieldSizeBytes, aliceZ.Length);
        Assert.Equal(bobZ, aliceZ);
    }, allowExtraction: true);

    // The export check runs before the peer is looked at: even garbage gets the policy refusal.
    [Fact]
    public void DeriveRawSecret_DefaultPolicy_IsRefusedBeforeThePeerIsRead() => WithEcKey(P256, alice =>
        Assert.Throws<CryptoPolicyViolationException>(() => alice.DeriveRawSecret([0x30, 0x00])));

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecret_PeerOnAnotherCurve_Throws() => WithEcKey(P256, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP384);
        Assert.Throws<Pkcs11ArgumentException>(() => alice.DeriveRawSecret(bob.ExportSubjectPublicKeyInfo()));
    }, allowExtraction: true);

    // A point off the curve is the invalid-curve attack's input; it must never reach C_DeriveKey.
    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecret_PointOffTheCurve_Throws() => WithEcKey(P256, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        ECParameters peer = bob.ExportParameters(includePrivateParameters: false);
        peer.Q.Y![^1] ^= 1;

        Assert.Throws<Pkcs11ArgumentException>(() => alice.DeriveRawSecret(SubjectPublicKeyInfoEncoding.EncodeEc(peer)));
    }, allowExtraction: true);

    [Fact]
    public void DeriveRawSecret_PeerOfAnotherAlgorithm_Throws() => WithEcKey(P256, alice =>
    {
        using var rsa = RSA.Create(2048);
        Assert.Throws<Pkcs11ArgumentException>(() => alice.DeriveRawSecret(rsa.ExportSubjectPublicKeyInfo()));
    }, allowExtraction: true);

    [Fact]
    public void DeriveRawSecret_NotASubjectPublicKeyInfo_Throws() => WithEcKey(P256, alice =>
    {
        var ex = Assert.Throws<ArgumentException>(() => alice.DeriveRawSecret([0x04, 0x01, 0x02]));
        Assert.Equal("peerSubjectPublicKeyInfo", ex.ParamName);
    }, allowExtraction: true);

    // RFC 5480 permits compressed points, but the token needs the uncompressed form and decompressing
    // is not this library's job.
    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecret_CompressedPoint_Throws() => WithEcKey(P256, alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        ECParameters p = bob.ExportParameters(includePrivateParameters: false);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(SubjectPublicKeyInfoEncoding.EcPublicKeyOid);
                writer.WriteObjectIdentifier(P256);
            }
            writer.WriteBitString([(byte)(0x02 | (p.Q.Y![^1] & 1)), .. p.Q.X!]);
        }

        var ex = Assert.Throws<ArgumentException>(() => alice.DeriveRawSecret(writer.Encode()));
        Assert.Equal("peerSubjectPublicKeyInfo", ex.ParamName);
    }, allowExtraction: true);

    [Fact]
    public void DeriveRawSecret_SecretKey_IsNotSupported() => WithAesKey(key =>
        Assert.Throws<NotSupportedException>(() => key.DeriveRawSecret([])));
}
