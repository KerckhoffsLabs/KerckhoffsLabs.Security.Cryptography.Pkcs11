using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// ECDiffieHellmanPkcs11 over the in-process <c>ManagedSoftToken</c>: EC key pairs are generated on
/// the token and the adapter agrees via <c>CKM_ECDH1_DERIVE</c> + <see cref="CKD.CKD_NULL"/> (raw
/// secret read back from a session generic-secret, KDF applied in managed code). Every agreement is
/// cross-checked against a BCL <see cref="ECDiffieHellman"/> peer in both directions, mirroring the
/// SoftHSM test set without needing SoftHSM. Crypto cases are gated on named-curve support;
/// construction / argument-validation cases that throw before any native call stay <see cref="FactAttribute"/>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class ECDiffieHellmanPkcs11Tests_Managed
{
    // The BCL must be able to create an ECDH instance on the curves these tests use. This is true on
    // every supported platform but probed so a constrained host skips rather than fails the run.
    public static bool Supported { get; } = ProbeNamedCurves();

    private static bool ProbeNamedCurves()
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

    // prime239v1 (X9.62) is outside Pkcs11ECCurve's catalog, and its 239-bit field is not a whole number
    // of bytes. Available wherever the BCL's backend implements it (OpenSSL does; CNG does not).
    private const string Prime239v1Oid = "1.2.840.10045.3.1.4";

    public static bool Prime239v1Supported { get; } = ProbeCurve(Prime239v1Oid);

    private static bool ProbeCurve(string oid)
    {
        try
        {
            using (ECDiffieHellman.Create(BclECCurve.CreateFromValue(oid))) { }
            return true;
        }
        catch (PlatformNotSupportedException) { return false; }
        catch (CryptographicException) { return false; }
    }

    private static byte[] H(string hex) => Convert.FromHexString(hex);

    // Maps a named-curve name to the production Pkcs11ECCurve (token side) and the BCL ECCurve (peer side).
    private static (Pkcs11ECCurve token, BclECCurve bcl) Curves(string curve) => curve switch
    {
        "P-256" => (Pkcs11ECCurve.NamedCurves.NistP256, BclECCurve.NamedCurves.nistP256),
        "P-384" => (Pkcs11ECCurve.NamedCurves.NistP384, BclECCurve.NamedCurves.nistP384),
        "P-521" => (Pkcs11ECCurve.NamedCurves.NistP521, BclECCurve.NamedCurves.nistP521),
        "prime239v1" => (Pkcs11ECCurve.CreateFromValue(Prime239v1Oid, "prime239v1"), BclECCurve.CreateFromValue(Prime239v1Oid)),
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unknown curve."),
    };

    private static int FieldSize(string curve) => curve switch
    {
        "P-256" => 32,
        "P-384" => 48,
        "P-521" => 66,
        "prime239v1" => 30,
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unknown curve."),
    };

    // Generates an EC key pair on the token (private half CKA_DERIVE) and hands the adapter to the body.
    /// <summary>
    /// Opts the session in: every method on this adapter returns bytes read off the token, so the
    /// single gate in <c>BuildSecureKeyDefaults</c> refuses all of them by default.
    /// <c>WithEcdhStrict</c> keeps the default posture for the tests that assert the refusal.
    /// </summary>
    private static void WithEcdh(string curve, Action<ECDiffieHellmanPkcs11> body) =>
        WithEcdh(curve, body, allowExtraction: true);

    private static void WithEcdhStrict(string curve, Action<ECDiffieHellmanPkcs11> body) =>
        WithEcdh(curve, body, allowExtraction: false);

    private static void WithEcdh(string curve, Action<ECDiffieHellmanPkcs11> body, bool allowExtraction)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using IDisposable? insecure = allowExtraction ? session.UsePolicy(CryptoPolicy.AllowInsecure) : null;
        using var key = session.GenerateEcKeyPair(Curves(curve).token);
        using var ecdh = new ECDiffieHellmanPkcs11(key);
        body(ecdh);
    }

    // === Real crypto: cross-checked against the BCL (mirrors the SoftHSM set) =============

    [Theory(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    public void DeriveKeyFromHash_AgreesWithBcl(string curve) => WithEcdh(curve, alice =>
    {
        using var bob = ECDiffieHellman.Create(Curves(curve).bcl);

        byte[] aliceKey = alice.DeriveKeyFromHash(bob.PublicKey, HashAlgorithmName.SHA256);
        byte[] bobKey = bob.DeriveKeyFromHash(alice.PublicKey, HashAlgorithmName.SHA256);

        Assert.Equal(32, aliceKey.Length);
        Assert.Equal(bobKey, aliceKey);
    });

    [Theory(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    public void DeriveKeyFromHash_WithPrependAppend_AgreesWithBcl(string curve) => WithEcdh(curve, alice =>
    {
        using var bob = ECDiffieHellman.Create(Curves(curve).bcl);
        byte[] prepend = [1, 2, 3];
        byte[] append = [9, 8, 7, 6];

        byte[] aliceKey = alice.DeriveKeyFromHash(bob.PublicKey, HashAlgorithmName.SHA384, prepend, append);
        byte[] bobKey = bob.DeriveKeyFromHash(alice.PublicKey, HashAlgorithmName.SHA384, prepend, append);

        Assert.Equal(bobKey, aliceKey);
    });

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveKeyFromHmac_AgreesWithBcl() => WithEcdh("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        byte[] hmacKey = [0xAA, 0xBB, 0xCC, 0xDD];

        byte[] aliceKey = alice.DeriveKeyFromHmac(bob.PublicKey, HashAlgorithmName.SHA256, hmacKey, null, null);
        byte[] bobKey = bob.DeriveKeyFromHmac(alice.PublicKey, HashAlgorithmName.SHA256, hmacKey, null, null);

        Assert.Equal(bobKey, aliceKey);
    });

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveKeyFromHmac_NullKey_UsesSecret_AgreesWithBcl() => WithEcdh("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

        byte[] aliceKey = alice.DeriveKeyFromHmac(bob.PublicKey, HashAlgorithmName.SHA256, hmacKey: null, null, null);
        byte[] bobKey = bob.DeriveKeyFromHmac(alice.PublicKey, HashAlgorithmName.SHA256, hmacKey: null, null, null);

        Assert.Equal(bobKey, aliceKey);
    });

    [Theory(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void DeriveRawSecretAgreement_MatchesBcl(string curve) => WithEcdh(curve, alice =>
    {
        using var bob = ECDiffieHellman.Create(Curves(curve).bcl);

        byte[] aliceZ = alice.DeriveRawSecretAgreement(bob.PublicKey);
        byte[] bobZ = bob.DeriveRawSecretAgreement(alice.PublicKey);

        Assert.Equal(FieldSize(curve), aliceZ.Length);
        Assert.Equal(bobZ, aliceZ);
    });

    // Outside the catalog the adapter sizes the secret from the local key's CKA_EC_POINT: 30-byte
    // coordinates for a 239-bit field.
    [Fact(SkipUnless = nameof(Prime239v1Supported), Skip = "Requires " + nameof(Prime239v1Supported))]
    public void DeriveRawSecretAgreement_CurveOutsideTheCatalog_MatchesBcl() => WithEcdh("prime239v1", alice =>
    {
        Assert.Null(Curves("prime239v1").token.FieldSizeBits);
        using var bob = ECDiffieHellman.Create(Curves("prime239v1").bcl);

        byte[] aliceZ = alice.DeriveRawSecretAgreement(bob.PublicKey);
        byte[] bobZ = bob.DeriveRawSecretAgreement(alice.PublicKey);

        Assert.Equal(FieldSize("prime239v1"), aliceZ.Length);
        Assert.Equal(bobZ, aliceZ);
    });

    // The field size comes from the token's own CKA_EC_POINT, so a peer whose coordinates don't match is
    // refused even though no catalog lists the curve. Without that fallback this peer's 32-byte X would
    // have set the size, and the mismatch would only surface (if at all) in the point-on-curve check.
    [Fact(SkipUnless = nameof(Prime239v1Supported), Skip = "Requires " + nameof(Prime239v1Supported))]
    public void DeriveRawSecretAgreement_CurveOutsideTheCatalog_PeerCoordinateLengthMismatch_Throws() => WithEcdh("prime239v1", alice =>
    {
        int wrongSize = FieldSize("prime239v1") + 2;
        var badPeer = new FixedPublicKey(new ECParameters
        {
            Curve = Curves("prime239v1").bcl,
            Q = new ECPoint { X = new byte[wrongSize], Y = new byte[wrongSize] },
        });

        var ex = Assert.Throws<Pkcs11ArgumentException>(() => alice.DeriveRawSecretAgreement(badPeer));
        Assert.Contains("30-byte field size", ex.Message, StringComparison.Ordinal);
    });

    // === A curve outside the built-in set, described through Pkcs11LibraryOptions.CurveCatalog ===

    private static readonly Pkcs11CurveCatalog Prime239v1Catalog =
        Pkcs11CurveCatalog.Default.With(new Pkcs11CurveInfo(Prime239v1Oid, "prime239v1", 239));

    // AllowInsecure: the default policy refuses both a key on an unlisted curve and the raw-secret read-back.
    private static void WithPrime239v1Catalog(Action<ECDiffieHellmanPkcs11> body)
    {
        using var library = new ManagedSoftToken().Load(new Pkcs11LibraryOptions { CurveCatalog = Prime239v1Catalog });
        using var session = ManagedToken.OpenSession(library);
        using IDisposable insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using var key = session.GenerateEcKeyPair(Curves("prime239v1").token);
        using var ecdh = new ECDiffieHellmanPkcs11(key);
        body(ecdh);
    }

    [Fact(SkipUnless = nameof(Prime239v1Supported), Skip = "Requires " + nameof(Prime239v1Supported))]
    public void KeySize_CurveInTheLibraryCatalog_IsItsFieldSize() => WithPrime239v1Catalog(alice =>
        Assert.Equal(239, alice.KeySize));

    [Fact(SkipUnless = nameof(Prime239v1Supported), Skip = "Requires " + nameof(Prime239v1Supported))]
    public void KeySize_CurveOutsideTheLibraryCatalog_StaysAtBclDefault() => WithEcdh("prime239v1", alice =>
        Assert.Equal(0, alice.KeySize));

    [Fact(SkipUnless = nameof(Prime239v1Supported), Skip = "Requires " + nameof(Prime239v1Supported))]
    public void DeriveRawSecretAgreement_CurveInTheLibraryCatalog_MatchesBcl() => WithPrime239v1Catalog(alice =>
    {
        using var bob = ECDiffieHellman.Create(Curves("prime239v1").bcl);

        byte[] aliceZ = alice.DeriveRawSecretAgreement(bob.PublicKey);
        byte[] bobZ = bob.DeriveRawSecretAgreement(alice.PublicKey);

        Assert.Equal(FieldSize("prime239v1"), aliceZ.Length);
        Assert.Equal(bobZ, aliceZ);
    });

    // With the catalog entry, the coordinate-length check that only built-in curves used to get runs:
    // the refusal names the field size, so it is that check, not the point-on-curve one, that caught it.
    [Fact(SkipUnless = nameof(Prime239v1Supported), Skip = "Requires " + nameof(Prime239v1Supported))]
    public void DeriveRawSecretAgreement_CurveInTheLibraryCatalog_PeerCoordinateLengthMismatch_Throws() => WithPrime239v1Catalog(alice =>
    {
        int wrongSize = FieldSize("prime239v1") + 2;
        var badPeer = new FixedPublicKey(new ECParameters
        {
            Curve = Curves("prime239v1").bcl,
            Q = new ECPoint { X = new byte[wrongSize], Y = new byte[wrongSize] },
        });

        var ex = Assert.Throws<Pkcs11ArgumentException>(() => alice.DeriveRawSecretAgreement(badPeer));
        Assert.Contains("30-byte field size", ex.Message, StringComparison.Ordinal);
    });

    // === The AllowInsecure policy ============================================================

    /// <summary>
    /// Every method on this adapter returns key bytes read off the token, so all of them are refused
    /// under the default posture — not just the raw-secret one.
    /// </summary>
    /// <remarks>
    /// The refusal comes from <c>Pkcs11SessionCore.BuildSecureKeyDefaults</c>, the single place that
    /// decides whether extractable key material may be created. The adapter carries no guard of its
    /// own, which is the point: there is nothing here that can drift out of step with the policy, and
    /// a new adapter cannot forget to apply it.
    /// </remarks>
    [Theory(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    [InlineData("raw")]
    [InlineData("hash")]
    [InlineData("hmac")]
    [InlineData("material")]
    public void WithoutAllowInsecure_EveryDerivationIsRefused(string method) => WithEcdhStrict("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

        Assert.Throws<CryptoPolicyViolationException>(() => _ = method switch
        {
            "raw" => alice.DeriveRawSecretAgreement(bob.PublicKey),
            "hash" => alice.DeriveKeyFromHash(bob.PublicKey, HashAlgorithmName.SHA256, null, null),
            "hmac" => alice.DeriveKeyFromHmac(bob.PublicKey, HashAlgorithmName.SHA256, null, null, null),
            _ => alice.DeriveKeyMaterial(bob.PublicKey),
        });
    });

    /// <summary>With the opt-in, the same calls work — the gate refuses, it does not disable.</summary>
    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void WithAllowInsecure_DerivationWorks() => WithEcdh("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

        Assert.NotEmpty(alice.DeriveKeyFromHash(bob.PublicKey, HashAlgorithmName.SHA256, null, null));
        Assert.NotEmpty(alice.DeriveRawSecretAgreement(bob.PublicKey));
    });

    // Two on-token key pairs agree with each other, and each agrees with the BCL in both directions.
    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecret_BothOnTokenParties_Match_AndMatchBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure); // reads Z back on both sides

        using var aliceKey = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var bobKey = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var alice = new ECDiffieHellmanPkcs11(aliceKey);
        using var bob = new ECDiffieHellmanPkcs11(bobKey);

        Assert.Equal(
            alice.DeriveRawSecretAgreement(bob.PublicKey),
            bob.DeriveRawSecretAgreement(alice.PublicKey));

        using var bcl = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        Assert.Equal(
            bcl.DeriveRawSecretAgreement(alice.PublicKey),
            alice.DeriveRawSecretAgreement(bcl.PublicKey));
    }

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveKeyMaterial_AgreesWithBcl() => WithEcdh("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

        // DeriveKeyMaterial defaults to DeriveKeyFromHash with SHA-256.
        Assert.Equal(bob.DeriveKeyMaterial(alice.PublicKey), alice.DeriveKeyMaterial(bob.PublicKey));
    });

    // Known-answer: the raw secret Z is the x-coordinate of the scalar multiplication, so deriving
    // against a fixed BCL key pair (imported from a known vector) yields a fixed BCL agreement we can
    // reproduce on both sides. The token key is fresh each run, so the KAT pins the token<->BCL
    // agreement to the BCL's own computation for the same inputs (round-trip identity in both directions).
    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveKeyFromHash_KnownVectorPeer_RoundTripsBothDirections() => WithEcdh("P-256", alice =>
    {
        // RFC 5114 / SP 800-56A P-256 sample static key pair "dA" (a fixed, well-formed P-256 key).
        ECParameters fixedPeer = new()
        {
            Curve = BclECCurve.NamedCurves.nistP256,
            D = H("814264145F2F56F2E96A8E337A1284993FAF432A5ABCE59E867B7291D507A3AF"),
            Q = new ECPoint
            {
                X = H("2AF502F3BE8952F2C9B5A8D4160D09E97165BE50BC42AE4A5E8D3B4BA83AEB15"),
                Y = H("EB0FAF4CA986C4D38681A0F9872D79D56795BD4BFF6E6DE3C0F5015ECE5EFD85"),
            },
        };
        using var peer = ECDiffieHellman.Create(fixedPeer);

        byte[] fromToken = alice.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256);
        byte[] fromPeer = peer.DeriveKeyFromHash(alice.PublicKey, HashAlgorithmName.SHA256);
        Assert.Equal(32, fromToken.Length);
        Assert.Equal(fromPeer, fromToken);

        // Raw agreement must match the BCL's own raw agreement against the same token public key.
        Assert.Equal(
            peer.DeriveRawSecretAgreement(alice.PublicKey),
            alice.DeriveRawSecretAgreement(peer.PublicKey));
    });

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void PublicKey_ExportsTokenPoint() => WithEcdh("P-256", alice =>
    {
        ECParameters fromExport = alice.ExportParameters(includePrivateParameters: false);
        ECParameters fromPublicKey = alice.PublicKey.ExportParameters();

        Assert.Equal(fromExport.Q.X, fromPublicKey.Q.X);
        Assert.Equal(fromExport.Q.Y, fromPublicKey.Q.Y);
        Assert.Equal(BclECCurve.NamedCurves.nistP256.Oid.Value, fromPublicKey.Curve.Oid.Value);
    });

    // The exported public point must be a valid P-256 point the BCL can agree against.
    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void ExportedPublicKey_IsUsableByBcl() => WithEcdh("P-256", alice =>
    {
        ECParameters pub = alice.ExportParameters(includePrivateParameters: false);
        using var bobFromExport = ECDiffieHellman.Create(pub);
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

        // bob agreeing with the re-imported token point equals the token agreeing with bob.
        Assert.Equal(
            bob.DeriveRawSecretAgreement(bobFromExport.PublicKey),
            alice.DeriveRawSecretAgreement(bob.PublicKey));
    });

    // === Negative / not-supported (run on every platform) =================================

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveKeyTls_NotSupported() => WithEcdh("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        Assert.Throws<NotSupportedException>(
            () => alice.DeriveKeyTls(bob.PublicKey, new byte[16], new byte[64]));
    });

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void ExportParameters_Private_ThrowsInsecure() => WithEcdh("P-256", alice =>
        Assert.Throws<CryptoPolicyViolationException>(() => alice.ExportParameters(includePrivateParameters: true)));

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void ExportExplicitParameters_NotSupported() => WithEcdh("P-256", alice =>
        Assert.Throws<NotSupportedException>(() => alice.ExportExplicitParameters(includePrivateParameters: false)));

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void ImportParameters_NotSupported() => WithEcdh("P-256", alice =>
        Assert.Throws<NotSupportedException>(() => alice.ImportParameters(new ECParameters())));

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void GenerateKey_NotSupported() => WithEcdh("P-256", alice =>
        Assert.Throws<NotSupportedException>(() => alice.GenerateKey(BclECCurve.NamedCurves.nistP256)));

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveKeyFromHash_NullPeer_Throws() => WithEcdh("P-256", alice =>
        Assert.Throws<ArgumentNullException>(
            () => alice.DeriveKeyFromHash(null!, HashAlgorithmName.SHA256, null, null)));

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveKeyFromHash_EmptyHashName_Throws() => WithEcdh("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        var ex = Assert.Throws<ArgumentException>(
            () => alice.DeriveKeyFromHash(bob.PublicKey, default, null, null));
        Assert.Equal("hashAlgorithm", ex.ParamName);
    });

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecretAgreement_NullPeer_Throws() => WithEcdh("P-256", alice =>
        Assert.Throws<ArgumentNullException>(() => alice.DeriveRawSecretAgreement(null!)));

    // === Construction (throws before any native call) =====================================

    [Fact]
    public void Ctor_NullKey_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new ECDiffieHellmanPkcs11(null!));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public void Ctor_NonEcKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("gen").ValueLen(32).Sign().Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new ECDiffieHellmanPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }

    // === KeySize / LegalKeySizes =============================================
    // Regression coverage for the adapter never assigning KeySizeValue: KeySize was 0 and
    // LegalKeySizes threw NullReferenceException.

    [Theory(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    [InlineData("P-256", 256)]
    [InlineData("P-384", 384)]
    public void KeySize_ReflectsTokenCurve(string curve, int expectedBits) => WithEcdhStrict(curve, ecdh =>
        Assert.Equal(expectedBits, ecdh.KeySize));

    [Theory(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    [InlineData("P-256", 256)]
    [InlineData("P-384", 384)]
    public void LegalKeySizes_ReflectsTokenCurve(string curve, int expectedBits) => WithEcdhStrict(curve, ecdh =>
    {
        KeySizes[] sizes = ecdh.LegalKeySizes;
        KeySizes only = Assert.Single(sizes);
        Assert.Equal(expectedBits, only.MinSize);
        Assert.Equal(expectedBits, only.MaxSize);
    });

    // A real token can't be coaxed into failing to read CKA_EC_PARAMS — it's a required attribute of
    // every EC key object — so this drives the fallback's error path via a fake library.
    [Fact]
    public void KeySize_EcParamsAttributeFails_StaysAtBclDefault()
    {
        using var key = FakeKeys.Create(CKK.CKK_EC, _ => (CKR.CKR_DEVICE_ERROR, null));
        using var ecdh = new ECDiffieHellmanPkcs11(key);
        Assert.Equal(0, ecdh.KeySize);
    }

    // CKA_EC_PARAMS readable but not a DER-encoded named-curve OID: Pkcs11ECCurve.FromEcParams
    // throws ArgumentException, which the fallback must also treat as "unknown, leave default".
    [Fact]
    public void KeySize_EcParamsNotAValidOid_StaysAtBclDefault()
    {
        using var key = FakeKeys.Create(CKK.CKK_EC, _ => (CKR.CKR_OK, (byte[])[0xFF, 0xFF, 0xFF]));
        using var ecdh = new ECDiffieHellmanPkcs11(key);
        Assert.Equal(0, ecdh.KeySize);
    }

    // === Peer validation: invalid-curve / off-curve point rejection =========================
    // A peer key on a different (weaker) curve, or an off-curve point on the right curve, must
    // never reach CKM_ECDH1_DERIVE — PKCS#11 does not require the token to check either, and the
    // standard invalid-curve / small-subgroup attack recovers the token-resident private key one
    // residue at a time if it does (Antipa et al., PKC 2003).

    /// <summary>A test-only peer whose <see cref="ExportParameters()"/> returns a fixed, possibly
    /// malformed, value — lets a test hand the adapter a peer point a real BCL key could never
    /// produce (e.g. off-curve), which is exactly what an untrusted caller could pass in.</summary>
    private sealed class FixedPublicKey(ECParameters parameters) : ECDiffieHellmanPublicKey
    {
        public override ECParameters ExportParameters() => parameters;
    }

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveKeyFromHash_PeerOnDifferentCurve_Throws() => WithEcdh("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP384);
        Assert.Throws<Pkcs11ArgumentException>(
            () => alice.DeriveKeyFromHash(bob.PublicKey, HashAlgorithmName.SHA256, null, null));
    });

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveRawSecretAgreement_PeerOnDifferentCurve_Throws() => WithEcdh("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP384);
        Assert.Throws<Pkcs11ArgumentException>(() => alice.DeriveRawSecretAgreement(bob.PublicKey));
    });

    // Explicit curve parameters carry no OID: refused like any other curve mismatch, not a
    // NullReferenceException from reading the missing OID. The adapter decodes its peer through
    // SubjectPublicKeyInfo, which already refuses explicit parameters; the session overload taking
    // ECParameters hands them to the peer validator as is.
    // P-256 as explicit domain parameters (SEC 2 §2.4.2), built by hand: macOS cannot export them.
    private static readonly BclECCurve ExplicitNistP256 = new()
    {
        CurveType = BclECCurve.ECCurveType.PrimeShortWeierstrass,
        Prime = H("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
        A = H("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
        B = H("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
        G = new ECPoint
        {
            X = H("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
            Y = H("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
        },
        Order = H("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
        Cofactor = [0x01],
    };

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveSharedSecretEcdh_PeerWithExplicitCurveParameters_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var alice = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        ECParameters explicitPeer = bob.ExportParameters(includePrivateParameters: false);
        explicitPeer.Curve = ExplicitNistP256;

        var ex = Assert.Throws<Pkcs11ArgumentException>(() => session.DeriveSharedSecretEcdh(alice, explicitPeer));
        Assert.Contains("(peer public key is on curve unknown, expected nistP256)", ex.Message, StringComparison.Ordinal);
    }

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveKeyFromHash_OffCurvePoint_Throws() => WithEcdh("P-256", alice =>
    {
        // Right curve (P-256), right coordinate length, but a point that does not satisfy the
        // curve equation y^2 = x^3 - 3x + b — the invalid-curve attack's actual payload shape.
        int size = FieldSize("P-256");
        var badPeer = new FixedPublicKey(new ECParameters
        {
            Curve = BclECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = new byte[size], Y = new byte[size] }, // (0, 0) is not on the curve
        });
        Assert.Throws<Pkcs11ArgumentException>(
            () => alice.DeriveKeyFromHash(badPeer, HashAlgorithmName.SHA256, null, null));
    });

    [Fact(SkipUnless = nameof(Supported), Skip = "Requires " + nameof(Supported))]
    public void DeriveKeyFromHash_PeerCoordinateLengthMismatch_Throws() => WithEcdh("P-256", alice =>
    {
        // Claims the P-256 OID but hands over P-384-sized coordinates — same curve identity, wrong
        // field size, which the curve-equality check alone would miss.
        int wrongSize = FieldSize("P-384");
        var badPeer = new FixedPublicKey(new ECParameters
        {
            Curve = BclECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = new byte[wrongSize], Y = new byte[wrongSize] },
        });
        Assert.Throws<Pkcs11ArgumentException>(
            () => alice.DeriveKeyFromHash(badPeer, HashAlgorithmName.SHA256, null, null));
    });
}
