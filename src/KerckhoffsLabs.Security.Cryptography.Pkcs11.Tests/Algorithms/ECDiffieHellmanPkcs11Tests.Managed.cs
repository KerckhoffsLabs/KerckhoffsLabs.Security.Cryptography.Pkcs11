using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;
using Pkcs11ECCurve = KerckhoffsLabs.Security.Cryptography.Pkcs11.ECCurve;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// ECDiffieHellmanPkcs11 over the in-process <c>ManagedSoftToken</c>: EC key pairs are generated on
/// the token and the adapter agrees via <c>CKM_ECDH1_DERIVE</c> + <see cref="CKD.CKD_NULL"/> (raw
/// secret read back from a session generic-secret, KDF applied in managed code). Every agreement is
/// cross-checked against a BCL <see cref="ECDiffieHellman"/> peer in both directions, mirroring the
/// SoftHSM test set without needing SoftHSM. Crypto cases are gated on named-curve support;
/// construction / argument-validation cases that throw before any native call stay <see cref="FactAttribute"/>.
/// </summary>
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

    private static byte[] H(string hex) => Convert.FromHexString(hex);

    // Maps a named-curve name to the production ECCurve (token side) and the BCL ECCurve (peer side).
    private static (Pkcs11ECCurve token, BclECCurve bcl) Curves(string curve) => curve switch
    {
        "P-256" => (Pkcs11ECCurve.NamedCurves.NistP256, BclECCurve.NamedCurves.nistP256),
        "P-384" => (Pkcs11ECCurve.NamedCurves.NistP384, BclECCurve.NamedCurves.nistP384),
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unknown curve."),
    };

    private static int FieldSize(string curve) => curve switch
    {
        "P-256" => 32,
        "P-384" => 48,
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unknown curve."),
    };

    // Generates an EC key pair on the token (private half CKA_DERIVE) and hands the adapter to the body.
    /// <summary>
    /// Opts the workspace in: every method on this adapter returns bytes read off the token, so the
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
        using var workspace = ManagedToken.OpenWorkspace(library);
        if (allowExtraction) workspace.AllowInsecure = true;
        using var key = workspace.GenerateEcKeyPair(Curves(curve).token);
        using var ecdh = new ECDiffieHellmanPkcs11(key);
        body(ecdh);
    }

    // === Real crypto: cross-checked against the BCL (mirrors the SoftHSM set) =============

    [ConditionalTheory(nameof(Supported))]
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

    [ConditionalTheory(nameof(Supported))]
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

    [ConditionalFact(nameof(Supported))]
    public void DeriveKeyFromHmac_AgreesWithBcl() => WithEcdh("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        byte[] hmacKey = [0xAA, 0xBB, 0xCC, 0xDD];

        byte[] aliceKey = alice.DeriveKeyFromHmac(bob.PublicKey, HashAlgorithmName.SHA256, hmacKey, null, null);
        byte[] bobKey = bob.DeriveKeyFromHmac(alice.PublicKey, HashAlgorithmName.SHA256, hmacKey, null, null);

        Assert.Equal(bobKey, aliceKey);
    });

    [ConditionalFact(nameof(Supported))]
    public void DeriveKeyFromHmac_NullKey_UsesSecret_AgreesWithBcl() => WithEcdh("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

        byte[] aliceKey = alice.DeriveKeyFromHmac(bob.PublicKey, HashAlgorithmName.SHA256, hmacKey: null, null, null);
        byte[] bobKey = bob.DeriveKeyFromHmac(alice.PublicKey, HashAlgorithmName.SHA256, hmacKey: null, null, null);

        Assert.Equal(bobKey, aliceKey);
    });

    [ConditionalTheory(nameof(Supported))]
    [InlineData("P-256")]
    [InlineData("P-384")]
    public void DeriveRawSecretAgreement_MatchesBcl(string curve) => WithEcdh(curve, alice =>
    {
        using var bob = ECDiffieHellman.Create(Curves(curve).bcl);

        byte[] aliceZ = alice.DeriveRawSecretAgreement(bob.PublicKey);
        byte[] bobZ = bob.DeriveRawSecretAgreement(alice.PublicKey);

        Assert.Equal(FieldSize(curve), aliceZ.Length);
        Assert.Equal(bobZ, aliceZ);
    });

    // === The AllowInsecure gate ============================================================

    /// <summary>
    /// Every method on this adapter returns key bytes read off the token, so all of them are refused
    /// under the default posture — not just the raw-secret one.
    /// </summary>
    /// <remarks>
    /// The refusal comes from <c>Pkcs11Session.BuildSecureKeyDefaults</c>, the single place that
    /// decides whether extractable key material may be created. The adapter carries no guard of its
    /// own, which is the point: there is nothing here that can drift out of step with the policy, and
    /// a new adapter cannot forget to apply it.
    /// </remarks>
    [ConditionalTheory(nameof(Supported))]
    [InlineData("raw")]
    [InlineData("hash")]
    [InlineData("hmac")]
    [InlineData("material")]
    public void WithoutAllowInsecure_EveryDerivationIsRefused(string method) => WithEcdhStrict("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

        Assert.Throws<InsecureOperationException>(() => _ = method switch
        {
            "raw" => alice.DeriveRawSecretAgreement(bob.PublicKey),
            "hash" => alice.DeriveKeyFromHash(bob.PublicKey, HashAlgorithmName.SHA256, null, null),
            "hmac" => alice.DeriveKeyFromHmac(bob.PublicKey, HashAlgorithmName.SHA256, null, null, null),
            _ => alice.DeriveKeyMaterial(bob.PublicKey),
        });
    });

    /// <summary>With the opt-in, the same calls work — the gate refuses, it does not disable.</summary>
    [ConditionalFact(nameof(Supported))]
    public void WithAllowInsecure_DerivationWorks() => WithEcdh("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

        Assert.NotEmpty(alice.DeriveKeyFromHash(bob.PublicKey, HashAlgorithmName.SHA256, null, null));
        Assert.NotEmpty(alice.DeriveRawSecretAgreement(bob.PublicKey));
    });

    // Two on-token key pairs agree with each other, and each agrees with the BCL in both directions.
    [ConditionalFact(nameof(Supported))]
    public void DeriveRawSecret_BothOnTokenParties_Match_AndMatchBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        workspace.AllowInsecure = true; // reads Z back on both sides

        using var aliceKey = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var bobKey = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
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

    [ConditionalFact(nameof(Supported))]
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
    [ConditionalFact(nameof(Supported))]
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

    [ConditionalFact(nameof(Supported))]
    public void PublicKey_ExportsTokenPoint() => WithEcdh("P-256", alice =>
    {
        ECParameters fromExport = alice.ExportParameters(includePrivateParameters: false);
        ECParameters fromPublicKey = alice.PublicKey.ExportParameters();

        Assert.Equal(fromExport.Q.X, fromPublicKey.Q.X);
        Assert.Equal(fromExport.Q.Y, fromPublicKey.Q.Y);
        Assert.Equal(BclECCurve.NamedCurves.nistP256.Oid.Value, fromPublicKey.Curve.Oid.Value);
    });

    // The exported public point must be a valid P-256 point the BCL can agree against.
    [ConditionalFact(nameof(Supported))]
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

    [ConditionalFact(nameof(Supported))]
    public void DeriveKeyTls_NotSupported() => WithEcdh("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        Assert.Throws<NotSupportedException>(
            () => alice.DeriveKeyTls(bob.PublicKey, new byte[16], new byte[64]));
    });

    [ConditionalFact(nameof(Supported))]
    public void ExportParameters_Private_ThrowsInsecure() => WithEcdh("P-256", alice =>
        Assert.Throws<InsecureOperationException>(() => alice.ExportParameters(includePrivateParameters: true)));

    [ConditionalFact(nameof(Supported))]
    public void ExportExplicitParameters_NotSupported() => WithEcdh("P-256", alice =>
        Assert.Throws<NotSupportedException>(() => alice.ExportExplicitParameters(includePrivateParameters: false)));

    [ConditionalFact(nameof(Supported))]
    public void ImportParameters_NotSupported() => WithEcdh("P-256", alice =>
        Assert.Throws<NotSupportedException>(() => alice.ImportParameters(new ECParameters())));

    [ConditionalFact(nameof(Supported))]
    public void GenerateKey_NotSupported() => WithEcdh("P-256", alice =>
        Assert.Throws<NotSupportedException>(() => alice.GenerateKey(BclECCurve.NamedCurves.nistP256)));

    [ConditionalFact(nameof(Supported))]
    public void DeriveKeyFromHash_NullPeer_Throws() => WithEcdh("P-256", alice =>
        Assert.Throws<ArgumentNullException>(
            () => alice.DeriveKeyFromHash(null!, HashAlgorithmName.SHA256, null, null)));

    [ConditionalFact(nameof(Supported))]
    public void DeriveKeyFromHash_EmptyHashName_Throws() => WithEcdh("P-256", alice =>
    {
        using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        var ex = Assert.Throws<ArgumentException>(
            () => alice.DeriveKeyFromHash(bob.PublicKey, default, null, null));
        Assert.Equal("hashAlgorithm", ex.ParamName);
    });

    [ConditionalFact(nameof(Supported))]
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
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("gen").ValueLen(32).Sign().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new ECDiffieHellmanPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }
}
