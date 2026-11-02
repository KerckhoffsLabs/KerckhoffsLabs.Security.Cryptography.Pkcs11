using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using CsCheck;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

// CKM_RSA_PKCS is used deliberately here to hit MapRsaSignMechanism's "no managed equivalent" arm
// (raw RSA carries its hash inside a DigestInfo, not at the mechanism level) — mechanism security is
// not what this test pins, so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11008
// SHA-1 mechanisms are used on purpose: the synthesis tests cover every mapped mechanism, and the
// policy tests pin that the managed fallback refuses them under Recommended (and allows legacy
// verification under NistApproved), and that PKCS#1 v1.5 over a SHA-1 digest is refused.
#pragma warning disable KLPKCS11009, KLPKCS11010

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Hermetic coverage for Pkcs11Key.Verify's managed-verification fallback (GetSynthesizedRsaParameters
/// / GetSynthesizedEcParameters / VerifyRsaInManaged / VerifyEcInManaged / MapRsaSignMechanism /
/// MapEcdsaMechanism) — taken only when the key has no CKO_PUBLIC_KEY companion on the token. No
/// backend in this project's test matrix exercises it: ManagedSoftToken's C_GenerateKeyPair always
/// creates both handles (see <c>ManagedSoftToken.Asym.cs</c>), and the real-backend suites that target
/// this exact path (<c>Pkcs11KeyPublicSynthesisTests.*</c>) need a native module this sandbox can't
/// load. Drive it directly instead: <see cref="FakeKeys"/> builds a private-only Pkcs11Key whose
/// CKA_MODULUS/CKA_PUBLIC_EXPONENT (RSA) or CKA_EC_POINT/CKA_EC_PARAMS (EC) answer with a real
/// BCL-generated public key, and a real signature — produced independently by that same managed key
/// — is verified through the fallback, so this is a genuine round trip, not just "doesn't throw".
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11KeyVerifyManagedFallbackTests
{
    private static readonly byte[] Data = Encoding.UTF8.GetBytes("verify via synthesized public key");

    // The synthesis tests below pin the fallback's mechanics across every mechanism it maps, including
    // SHA-1 and raw RSA on purpose, so they run under AllowInsecure. The policy on this path is pinned
    // separately in the "Policy on the managed fallback" section.
    private static readonly ICryptoPolicy Mechanics = CryptoPolicy.AllowInsecure;

    // === RSA =================================================================

    // xUnit1044: HashAlgorithmName/RSASignaturePadding aren't serializable, which breaks Test
    // Explorer's per-row enumeration — carry only the (serializable) CKM and derive the hash/padding
    // from it in the test body instead, since each mechanism determines them uniquely anyway.
    public static TheoryData<CKM> RsaMechanisms() =>
    [
        CKM.CKM_SHA1_RSA_PKCS,
        CKM.CKM_SHA256_RSA_PKCS,
        CKM.CKM_SHA384_RSA_PKCS,
        CKM.CKM_SHA512_RSA_PKCS,
        CKM.CKM_SHA1_RSA_PKCS_PSS,
        CKM.CKM_SHA256_RSA_PKCS_PSS,
        CKM.CKM_SHA384_RSA_PKCS_PSS,
        CKM.CKM_SHA512_RSA_PKCS_PSS,
    ];

    private static (HashAlgorithmName Hash, RSASignaturePadding Padding) HashAndPaddingFor(CKM mechanismType) => mechanismType switch
    {
        CKM.CKM_SHA1_RSA_PKCS => (HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1),
        CKM.CKM_SHA256_RSA_PKCS => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
        CKM.CKM_SHA384_RSA_PKCS => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
        CKM.CKM_SHA512_RSA_PKCS => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
        CKM.CKM_SHA1_RSA_PKCS_PSS => (HashAlgorithmName.SHA1, RSASignaturePadding.Pss),
        CKM.CKM_SHA256_RSA_PKCS_PSS => (HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
        CKM.CKM_SHA384_RSA_PKCS_PSS => (HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
        CKM.CKM_SHA512_RSA_PKCS_PSS => (HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
        CKM.CKM_SHA3_256_RSA_PKCS => (HashAlgorithmName.SHA3_256, RSASignaturePadding.Pkcs1),
        CKM.CKM_SHA3_384_RSA_PKCS => (HashAlgorithmName.SHA3_384, RSASignaturePadding.Pkcs1),
        CKM.CKM_SHA3_512_RSA_PKCS => (HashAlgorithmName.SHA3_512, RSASignaturePadding.Pkcs1),
        CKM.CKM_SHA3_256_RSA_PKCS_PSS => (HashAlgorithmName.SHA3_256, RSASignaturePadding.Pss),
        CKM.CKM_SHA3_384_RSA_PKCS_PSS => (HashAlgorithmName.SHA3_384, RSASignaturePadding.Pss),
        CKM.CKM_SHA3_512_RSA_PKCS_PSS => (HashAlgorithmName.SHA3_512, RSASignaturePadding.Pss),
        _ => throw new ArgumentOutOfRangeException(nameof(mechanismType)),
    };

    // A CKM_SHAx_RSA_PKCS_PSS mechanism carries the CK_RSA_PKCS_PSS_PARAMS the spec requires, here the
    // ones the library's own sign path builds (MGF1 with the message hash, salt = hash length); the
    // PKCS#1 v1.5 mechanisms take none.
    private static Mechanism MechanismFor(CKM mechanismType)
    {
        var (hash, padding) = HashAndPaddingFor(mechanismType);
        return padding == RSASignaturePadding.Pss
            ? Pkcs11MechanismMap.RsaPssSign(hash, saltLength: -1)
            : new Mechanism(mechanismType);
    }

    // The SHA-3 mechanisms verify with the BCL's SHA-3, so they need the host to have it.
    public static TheoryData<CKM> RsaSha3Mechanisms() =>
    [
        CKM.CKM_SHA3_256_RSA_PKCS,
        CKM.CKM_SHA3_384_RSA_PKCS,
        CKM.CKM_SHA3_512_RSA_PKCS,
        CKM.CKM_SHA3_256_RSA_PKCS_PSS,
        CKM.CKM_SHA3_384_RSA_PKCS_PSS,
        CKM.CKM_SHA3_512_RSA_PKCS_PSS,
    ];

    [Theory]
    [MemberData(nameof(RsaMechanisms))]
    public void Verify_PrivateOnlyRsaKey_SynthesizesPublicKeyAndVerifies(CKM mechanismType)
        => AssertSynthesizedRsaVerify(mechanismType);

    [Theory(SkipUnless = nameof(SHA3_256.IsSupported), SkipType = typeof(SHA3_256), Skip = "Requires " + nameof(SHA3_256.IsSupported))]
    [MemberData(nameof(RsaSha3Mechanisms))]
    public void Verify_PrivateOnlyRsaKey_Sha3_SynthesizesPublicKeyAndVerifies(CKM mechanismType)
        => AssertSynthesizedRsaVerify(mechanismType);

    // Without the platform's SHA-3 the managed verify fails as the BCL's own RSA does.
    [Theory]
    [MemberData(nameof(RsaSha3Mechanisms))]
    public void Verify_PrivateOnlyRsaKey_Sha3_WithoutPlatformSha3_FailsAsTheBcl(CKM mechanismType)
    {
        Assert.SkipWhen(SHA3_256.IsSupported, "The host has SHA3-256.");
        var (hash, padding) = HashAndPaddingFor(mechanismType);
        using var rsa = RSA.Create(2048);
        RSAParameters pub = rsa.ExportParameters(includePrivateParameters: false);

        using var fake = FakeKeys.Create(CKK.CKK_RSA, ca => ca switch
        {
            CKA.CKA_MODULUS => (CKR.CKR_OK, pub.Modulus),
            CKA.CKA_PUBLIC_EXPONENT => (CKR.CKR_OK, pub.Exponent),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        }, Mechanics);
        Pkcs11Key key = fake;

        Exception expected = Assert.ThrowsAny<Exception>(() => rsa.VerifyData(Data, new byte[256], hash, padding));
        Exception actual = Assert.ThrowsAny<Exception>(() => key.Verify(MechanismFor(mechanismType), Data, new byte[256]));
        Assert.Equal(expected.GetType(), actual.GetType());
    }

    private static void AssertSynthesizedRsaVerify(CKM mechanismType)
    {
        var (hash, padding) = HashAndPaddingFor(mechanismType);
        using var rsa = RSA.Create(2048);
        RSAParameters pub = rsa.ExportParameters(includePrivateParameters: false);
        byte[] signature = rsa.SignData(Data, hash, padding);

        using var fake = FakeKeys.Create(CKK.CKK_RSA, ca => ca switch
        {
            CKA.CKA_MODULUS => (CKR.CKR_OK, pub.Modulus),
            CKA.CKA_PUBLIC_EXPONENT => (CKR.CKR_OK, pub.Exponent),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        }, Mechanics);
        Pkcs11Key key = fake;

        Assert.True(key.Verify(MechanismFor(mechanismType), Data, signature));

        byte[] tampered = [.. signature];
        tampered[0] ^= 0xFF;
        Assert.False(key.Verify(MechanismFor(mechanismType), Data, tampered));
    }

    [Fact]
    public void Verify_PrivateOnlyRsaKey_UnsupportedMechanism_Throws()
    {
        using var rsa = RSA.Create(2048);
        RSAParameters pub = rsa.ExportParameters(includePrivateParameters: false);

        using var fake = FakeKeys.Create(CKK.CKK_RSA, ca => ca switch
        {
            CKA.CKA_MODULUS => (CKR.CKR_OK, pub.Modulus),
            CKA.CKA_PUBLIC_EXPONENT => (CKR.CKR_OK, pub.Exponent),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        }, Mechanics);
        Pkcs11Key key = fake;

        var ex = Assert.Throws<NotSupportedException>(
            () => key.Verify(new Mechanism(CKM.CKM_RSA_PKCS), Data, new byte[256]));
        Assert.Contains("Managed RSA verify is not implemented", ex.Message);
    }

    [Fact]
    public void Verify_PrivateOnlyRsaKey_AttributesSensitive_ThrowsHandleInvalid()
    {
        using var fake = FakeKeys.Create(CKK.CKK_RSA, _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null), Mechanics);
        Pkcs11Key key = fake;

        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => key.Verify(new Mechanism(CKM.CKM_SHA256_RSA_PKCS), Data, new byte[256]));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);

        var digest = Assert.ThrowsAny<Pkcs11Exception>(
            () => key.VerifyPkcs1Digest(HashAlgorithmName.SHA256, new byte[32], new byte[256]));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, digest.ReturnValue);
    }

    // A modulus or exponent the token returns empty or zero is no public key: refused with the
    // attribute named, rather than handed to the BCL, which throws IndexOutOfRangeException for an
    // empty one.
    [Theory]
    [InlineData(CKA.CKA_MODULUS, 0)]
    [InlineData(CKA.CKA_MODULUS, 256)]
    [InlineData(CKA.CKA_PUBLIC_EXPONENT, 0)]
    [InlineData(CKA.CKA_PUBLIC_EXPONENT, 1)]
    public void Verify_PrivateOnlyRsaKey_EmptyOrZeroValue_ThrowsAttributeValueInvalid(CKA attribute, int zeroBytes)
    {
        using var rsa = RSA.Create(2048);
        RSAParameters pub = rsa.ExportParameters(includePrivateParameters: false);
        using var fake = FakeKeys.Create(CKK.CKK_RSA, ca => ca switch
        {
            _ when ca == attribute => (CKR.CKR_OK, new byte[zeroBytes]),
            CKA.CKA_MODULUS => (CKR.CKR_OK, pub.Modulus),
            CKA.CKA_PUBLIC_EXPONENT => (CKR.CKR_OK, pub.Exponent),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        }, Mechanics);
        Pkcs11Key key = fake;

        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => key.Verify(new Mechanism(CKM.CKM_SHA256_RSA_PKCS), Data, new byte[256]));
        Assert.Equal(CKR.CKR_ATTRIBUTE_VALUE_INVALID, ex.ReturnValue);
        Assert.Contains(attribute.ToString(), ex.Message);

        var digest = Assert.ThrowsAny<Pkcs11Exception>(
            () => key.VerifyPkcs1Digest(HashAlgorithmName.SHA256, new byte[32], new byte[256]));
        Assert.Equal(CKR.CKR_ATTRIBUTE_VALUE_INVALID, digest.ReturnValue);
    }

    // === EC ==================================================================

    // CKA_EC_POINT is a DER OCTET STRING wrapping the uncompressed point (0x04 || X || Y) — same
    // encoding ManagedSoftToken.Asym.cs uses for a real (both-handle) EC key pair.
    private static byte[] EncodeEcPoint(ECPoint q)
    {
        byte[] point = [0x04, .. q.X!, .. q.Y!];
        return [0x04, (byte)point.Length, .. point];
    }

    [Fact]
    public void Verify_PrivateOnlyEcKey_RawEcdsa_VerifiesViaHash()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters pub = ec.ExportParameters(includePrivateParameters: false);
        byte[] hash = SHA256.HashData(Data);
        byte[] signature = ec.SignHash(hash);

        using var fake = FakeKeys.Create(CKK.CKK_EC, ca => ca switch
        {
            CKA.CKA_EC_POINT => (CKR.CKR_OK, EncodeEcPoint(pub.Q)),
            CKA.CKA_EC_PARAMS => (CKR.CKR_OK, Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        }, Mechanics);
        Pkcs11Key key = fake;

        Assert.True(key.Verify(new Mechanism(CKM.CKM_ECDSA), hash, signature));

        byte[] tampered = [.. hash];
        tampered[0] ^= 0xFF;
        Assert.False(key.Verify(new Mechanism(CKM.CKM_ECDSA), tampered, signature));
    }

    [Theory]
    [InlineData(CKM.CKM_ECDSA_SHA1, "SHA1")]
    [InlineData(CKM.CKM_ECDSA_SHA256, "SHA256")]
    [InlineData(CKM.CKM_ECDSA_SHA384, "SHA384")]
    [InlineData(CKM.CKM_ECDSA_SHA512, "SHA512")]
    [InlineData(CKM.CKM_ECDSA_SHA3_256, "SHA3-256")]
    [InlineData(CKM.CKM_ECDSA_SHA3_384, "SHA3-384")]
    [InlineData(CKM.CKM_ECDSA_SHA3_512, "SHA3-512")]
    public void Verify_PrivateOnlyEcKey_CombinedMechanism_SynthesizesPublicKeyAndVerifies(
        CKM mechanismType, string hashName)
    {
        Assert.SkipWhen(hashName.StartsWith("SHA3-", StringComparison.Ordinal) && !SHA3_256.IsSupported, "The host BCL has no SHA-3.");
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters pub = ec.ExportParameters(includePrivateParameters: false);
        var hash = new HashAlgorithmName(hashName);
        byte[] signature = ec.SignData(Data, hash);

        using var fake = FakeKeys.Create(CKK.CKK_EC, ca => ca switch
        {
            CKA.CKA_EC_POINT => (CKR.CKR_OK, EncodeEcPoint(pub.Q)),
            CKA.CKA_EC_PARAMS => (CKR.CKR_OK, Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        }, Mechanics);
        Pkcs11Key key = fake;

        Assert.True(key.Verify(new Mechanism(mechanismType), Data, signature));

        byte[] tampered = [.. signature];
        tampered[0] ^= 0xFF;
        Assert.False(key.Verify(new Mechanism(mechanismType), Data, tampered));
    }

    [Fact]
    public void Verify_PrivateOnlyEcKey_UnsupportedMechanism_Throws()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters pub = ec.ExportParameters(includePrivateParameters: false);

        using var fake = FakeKeys.Create(CKK.CKK_EC, ca => ca switch
        {
            CKA.CKA_EC_POINT => (CKR.CKR_OK, EncodeEcPoint(pub.Q)),
            CKA.CKA_EC_PARAMS => (CKR.CKR_OK, Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        }, Mechanics);
        Pkcs11Key key = fake;

        // CKM_ECDSA_SHA224 is used here only because Pkcs11Key's managed-verify fallback (MapEcdsaMechanism)
        // has no case for it; the key runs under AllowInsecure so the policy lets it through to that arm.
        var ex = Assert.Throws<NotSupportedException>(
            () => key.Verify(new Mechanism(CKM.CKM_ECDSA_SHA224), Data, new byte[64]));
        Assert.Contains("Managed ECDSA verify is not implemented", ex.Message);
    }

    [Fact]
    public void Verify_PrivateOnlyEcKey_AttributesUnreadable_ThrowsHandleInvalid()
    {
        using var fake = FakeKeys.Create(CKK.CKK_EC, _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null), Mechanics);
        Pkcs11Key key = fake;

        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => key.Verify(new Mechanism(CKM.CKM_ECDSA_SHA256), Data, new byte[64]));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }

    // === Policy on the managed fallback ======================================
    // A key with no public handle verifies in managed code. The session policy must judge that
    // verification exactly as it judges one done on the token.

    private static FakeKey PrivateOnlyRsaKey(RSAParameters pub, ICryptoPolicy? policy) =>
        FakeKeys.Create(CKK.CKK_RSA, ca => ca switch
        {
            CKA.CKA_MODULUS => (CKR.CKR_OK, pub.Modulus),
            CKA.CKA_PUBLIC_EXPONENT => (CKR.CKR_OK, pub.Exponent),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        }, policy);

    [Theory]
    [InlineData(CKM.CKM_SHA1_RSA_PKCS)]
    [InlineData(CKM.CKM_SHA1_RSA_PKCS_PSS)]
    public void ManagedFallback_UnderRecommended_RefusesSha1RsaVerification(CKM mechanismType)
    {
        var (hash, padding) = HashAndPaddingFor(mechanismType);
        using var rsa = RSA.Create(2048);
        byte[] signature = rsa.SignData(Data, hash, padding);
        using var fake = PrivateOnlyRsaKey(rsa.ExportParameters(false), policy: null);
        Pkcs11Key key = fake;

        var ex = Assert.Throws<CryptoPolicyViolationException>(
            () => key.Verify(new Mechanism(mechanismType), Data, signature));
        Assert.Equal("Recommended", ex.PolicyName);
        Assert.Equal(mechanismType, ex.Mechanism);
    }

    [Fact]
    public void ManagedFallback_UnderRecommended_AllowsSha256RsaVerification()
    {
        using var rsa = RSA.Create(2048);
        byte[] signature = rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        using var fake = PrivateOnlyRsaKey(rsa.ExportParameters(false), policy: null);
        Pkcs11Key key = fake;

        Assert.True(key.Verify(MechanismFor(CKM.CKM_SHA256_RSA_PKCS_PSS), Data, signature));
    }

    // PKCS#1 v1.5 over a caller's digest takes the same fallback on a private-only key, judged as the
    // combined mechanism: allowed for SHA-256 under Recommended, refused for SHA-1.
    [Fact]
    public void ManagedFallback_Pkcs1DigestVerification_IsJudgedAsTheCombinedMechanism()
    {
        using var rsa = RSA.Create(2048);
        byte[] digest = SHA256.HashData(Data);
        byte[] signature = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var fake = PrivateOnlyRsaKey(rsa.ExportParameters(false), policy: null);
        Pkcs11Key key = fake;

        Assert.True(key.VerifyPkcs1Digest(HashAlgorithmName.SHA256, digest, signature));
        signature[0] ^= 0xFF;
        Assert.False(key.VerifyPkcs1Digest(HashAlgorithmName.SHA256, digest, signature));

        var e = Assert.Throws<CryptoPolicyViolationException>(
            () => key.VerifyPkcs1Digest(HashAlgorithmName.SHA1, SHA1.HashData(Data), signature));
        Assert.Equal(CKM.CKM_SHA1_RSA_PKCS, e.Mechanism);
    }

    [Fact]
    public void ManagedFallback_UnderRecommended_RefusesAnUnlistedVendorMechanism()
    {
        using var rsa = RSA.Create(2048);
        using var fake = PrivateOnlyRsaKey(rsa.ExportParameters(false), policy: null);
        Pkcs11Key key = fake;

        Assert.Throws<CryptoPolicyViolationException>(
            () => key.Verify(new Mechanism((CKM)0x8000_1234UL), Data, new byte[256]));
    }

    // NistApproved allows SHA-1 RSA signatures only for Verify (legacy use): proves the fallback reports
    // the verification direction, not just that it consults the policy.
    [Fact]
    public void ManagedFallback_UnderNistApproved_AllowsLegacySha1RsaVerification()
    {
        using var rsa = RSA.Create(2048);
        byte[] signature = rsa.SignData(Data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        using var fake = PrivateOnlyRsaKey(rsa.ExportParameters(false), CryptoPolicy.NistApproved);
        Pkcs11Key key = fake;

        Assert.True(key.Verify(new Mechanism(CKM.CKM_SHA1_RSA_PKCS), Data, signature));
    }

    [Fact]
    public void ManagedFallback_UnderRecommended_RefusesSha1EcdsaVerification()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters pub = ec.ExportParameters(includePrivateParameters: false);
        byte[] signature = ec.SignData(Data, HashAlgorithmName.SHA1);
        using var fake = FakeKeys.Create(CKK.CKK_EC, ca => ca switch
        {
            CKA.CKA_EC_POINT => (CKR.CKR_OK, EncodeEcPoint(pub.Q)),
            CKA.CKA_EC_PARAMS => (CKR.CKR_OK, Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        });
        Pkcs11Key key = fake;

        Assert.Throws<CryptoPolicyViolationException>(
            () => key.Verify(new Mechanism(CKM.CKM_ECDSA_SHA1), Data, signature));
    }

    // === RSA-PSS parameters on the managed fallback ==========================
    // The BCL verifies one PSS profile only: MGF1 with the message hash and a salt of the hash's length.
    // The token honours the caller's CK_RSA_PKCS_PSS_PARAMS, so a fallback that ignored them would answer
    // differently from the token for the same key and signature. It refuses any other parameters as the
    // token refuses parameters it cannot use (CKR_MECHANISM_PARAM_INVALID), never answering true or false.

    private static FakeKey PrivateOnlyRsaKey(RSA rsa) => PrivateOnlyRsaKey(rsa.ExportParameters(false), Mechanics);

    private static HashAlgorithmName HashOf(CKM hashAlg) => hashAlg switch
    {
        CKM.CKM_SHA_1 => HashAlgorithmName.SHA1,
        CKM.CKM_SHA256 => HashAlgorithmName.SHA256,
        CKM.CKM_SHA384 => HashAlgorithmName.SHA384,
        CKM.CKM_SHA512 => HashAlgorithmName.SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(hashAlg)),
    };

    private static HashAlgorithmName HashOf(CKG mgf) => mgf switch
    {
        CKG.CKG_MGF1_SHA1 => HashAlgorithmName.SHA1,
        CKG.CKG_MGF1_SHA256 => HashAlgorithmName.SHA256,
        CKG.CKG_MGF1_SHA384 => HashAlgorithmName.SHA384,
        CKG.CKG_MGF1_SHA512 => HashAlgorithmName.SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(mgf)),
    };

    // RFC 8017 §8.1.1 RSASSA-PSS-SIGN with any message hash, MGF1 hash and salt length: EMSA-PSS-ENCODE
    // (§9.1.1), then RSASP1 as a modular exponentiation with the private exponent. The BCL signs only its
    // own profile, so this is what produces the signatures that are valid under other parameters.
    private static byte[] PssSign(RSAParameters priv, ReadOnlySpan<byte> message, HashAlgorithmName hash, HashAlgorithmName mgfHash, int saltLength)
    {
        var n = new BigInteger(priv.Modulus, isUnsigned: true, isBigEndian: true);
        int modBits = (int)n.GetBitLength();
        int emBits = modBits - 1;
        int emLen = (emBits + 7) / 8;
        int k = priv.Modulus!.Length;

        byte[] mHash = CryptographicOperations.HashData(hash, message);
        byte[] salt = RandomNumberGenerator.GetBytes(saltLength);
        byte[] h = CryptographicOperations.HashData(hash, [.. new byte[8], .. mHash, .. salt]);

        byte[] db = new byte[emLen - h.Length - 1];
        db[db.Length - saltLength - 1] = 0x01;
        salt.CopyTo(db, db.Length - saltLength);
        byte[] mask = Mgf1(mgfHash, h, db.Length);
        for (int i = 0; i < db.Length; i++)
            db[i] ^= mask[i];
        db[0] &= (byte)(0xFF >> (8 * emLen - emBits));

        byte[] em = [.. db, .. h, 0xBC];
        var m = new BigInteger(em, isUnsigned: true, isBigEndian: true);
        var d = new BigInteger(priv.D, isUnsigned: true, isBigEndian: true);
        byte[] s = BigInteger.ModPow(m, d, n).ToByteArray(isUnsigned: true, isBigEndian: true);
        return [.. new byte[k - s.Length], .. s];
    }

    private static byte[] Mgf1(HashAlgorithmName hash, byte[] seed, int length)
    {
        var output = new List<byte>(length);
        for (uint counter = 0; output.Count < length; counter++)
        {
            byte[] c = [(byte)(counter >> 24), (byte)(counter >> 16), (byte)(counter >> 8), (byte)counter];
            output.AddRange(CryptographicOperations.HashData(hash, [.. seed, .. c]));
        }
        return [.. output.Take(length)];
    }

    // Pins the test signer: under the BCL's own profile its signature is one the BCL accepts.
    [Fact]
    public void PssSign_UnderTheBclProfile_IsASignatureTheBclAccepts()
    {
        using var rsa = RSA.Create(2048);
        byte[] signature = PssSign(rsa.ExportParameters(true), Data, HashAlgorithmName.SHA256, HashAlgorithmName.SHA256, 32);

        Assert.True(rsa.VerifyData(Data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    [Fact]
    public void ManagedFallback_Pss_MatchingParameters_Verifies()
    {
        using var rsa = RSA.Create(2048);
        byte[] signature = PssSign(rsa.ExportParameters(true), Data, HashAlgorithmName.SHA256, HashAlgorithmName.SHA256, 32);
        using var fake = PrivateOnlyRsaKey(rsa);
        Pkcs11Key key = fake;
        var mechanism = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));

        Assert.True(key.Verify(mechanism, Data, signature));
        byte[] tampered = [.. signature];
        tampered[^1] ^= 0x01;
        Assert.False(key.Verify(mechanism, Data, tampered));
    }

    // Each row's signature IS valid under the row's parameters: before the fix the fallback answered
    // false for it (the token answers true), or true for a signature made under other parameters.
    [Theory]
    [InlineData(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 0)]
    [InlineData(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 20)]
    [InlineData(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA1, 32)]
    [InlineData(CKM.CKM_SHA512, CKG.CKG_MGF1_SHA512, 64)]
    public void ManagedFallback_Pss_ParametersTheBclCannotVerify_AreRefused(CKM hashAlg, CKG mgf, int saltLength)
    {
        using var rsa = RSA.Create(2048);
        byte[] signature = PssSign(rsa.ExportParameters(true), Data, HashOf(hashAlg), HashOf(mgf), saltLength);
        using var fake = PrivateOnlyRsaKey(rsa);
        Pkcs11Key key = fake;
        var mechanism = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(hashAlg, mgf, saltLength));

        var ex = Assert.Throws<Pkcs11MechanismException>(() => key.Verify(mechanism, Data, signature));
        Assert.Equal(CKR.CKR_MECHANISM_PARAM_INVALID, ex.ReturnValue);
    }

    // The token's verdict the other way round: a caller that asks for a zero-length salt must not be
    // told a signature made with a 32-byte salt is valid.
    [Fact]
    public void ManagedFallback_Pss_ZeroSaltRequested_DoesNotAcceptAHashLengthSaltSignature()
    {
        using var rsa = RSA.Create(2048);
        byte[] signature = rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        using var fake = PrivateOnlyRsaKey(rsa);
        Pkcs11Key key = fake;
        var mechanism = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 0));

        var ex = Assert.Throws<Pkcs11MechanismException>(() => key.Verify(mechanism, Data, signature));
        Assert.Equal(CKR.CKR_MECHANISM_PARAM_INVALID, ex.ReturnValue);
    }

    // CKM_SHAx_RSA_PKCS_PSS requires CK_RSA_PKCS_PSS_PARAMS (PKCS#11 v3.1 §2.1.15), so no parameters, a
    // raw block the fallback cannot read, or a parameter object of another type is refused as a token does.
    public static TheoryData<string> NonPssParameters() => ["none", "raw", "oaep"];

    [Theory]
    [MemberData(nameof(NonPssParameters))]
    public void ManagedFallback_Pss_WithoutPssParameters_IsRefused(string parameters)
    {
        using var rsa = RSA.Create(2048);
        byte[] signature = rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        using var fake = PrivateOnlyRsaKey(rsa);
        Pkcs11Key key = fake;
        Mechanism mechanism = parameters switch
        {
            "none" => new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS),
            "raw" => new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, RawParameter.Of(CKM.CKM_SHA256_RSA_PKCS_PSS)),
            _ => new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)),
        };

        var ex = Assert.Throws<Pkcs11MechanismException>(() => key.Verify(mechanism, Data, signature));
        Assert.Equal(CKR.CKR_MECHANISM_PARAM_INVALID, ex.ReturnValue);
    }

    // The policy is asked first: a mechanism it refuses is refused as such, whatever its parameters.
    [Fact]
    public void ManagedFallback_Pss_PolicyRefusalComesBeforeTheParameterCheck()
    {
        using var rsa = RSA.Create(2048);
        using var fake = PrivateOnlyRsaKey(rsa.ExportParameters(false), policy: null);
        Pkcs11Key key = fake;
        var mechanism = new Mechanism(CKM.CKM_SHA1_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA512, 0));

        var ex = Assert.Throws<CryptoPolicyViolationException>(() => key.Verify(mechanism, Data, new byte[256]));
        Assert.Equal(CKM.CKM_SHA1_RSA_PKCS_PSS, ex.Mechanism);
    }

    // Over random hash / MGF1 hash / salt-length combinations, each signed under its own parameters: the
    // fallback either has the BCL's profile and answers what RSA.VerifyData answers, or refuses with
    // CKR_MECHANISM_PARAM_INVALID. It never answers a bool for parameters it did not verify under.
    [Fact]
    public void ManagedFallback_Pss_AnyParameters_MatchTheBclOrAreRefused()
    {
        // Index i of each array is one hash: its PSS mechanism, its CKM, its MGF1 and its output length.
        CKM[] mechanisms = [CKM.CKM_SHA1_RSA_PKCS_PSS, CKM.CKM_SHA256_RSA_PKCS_PSS, CKM.CKM_SHA384_RSA_PKCS_PSS, CKM.CKM_SHA512_RSA_PKCS_PSS];
        CKM[] hashes = [CKM.CKM_SHA_1, CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512];
        CKG[] mgfs = [CKG.CKG_MGF1_SHA1, CKG.CKG_MGF1_SHA256, CKG.CKG_MGF1_SHA384, CKG.CKG_MGF1_SHA512];
        int[] lengths = [20, 32, 48, 64];
        using var rsa = RSA.Create(2048);
        RSAParameters priv = rsa.ExportParameters(true);
        using var fake = PrivateOnlyRsaKey(rsa);
        Pkcs11Key key = fake;

        int verified = 0, refused = 0;

        // Each parameter is the mechanism's own half the time, so the BCL's profile turns up often.
        var inputs =
            from m in Gen.Int[0, 3]
            from h in Gen.Frequency((1, Gen.Const(m)), (1, Gen.Int[0, 3]))
            from g in Gen.Frequency((1, Gen.Const(m)), (1, Gen.Int[0, 3]))
            from saltLength in Gen.Frequency((1, Gen.Const(lengths[m])), (1, Gen.Int[0, 64]))
            from tamper in Gen.Bool
            select (m, h, g, saltLength, tamper);

        inputs.Sample(input =>
        {
            var (m, h, g, saltLength, tamper) = input;
            byte[] signature = PssSign(priv, Data, HashOf(hashes[h]), HashOf(mgfs[g]), saltLength);
            if (tamper)
                signature[^1] ^= 0x01;
            var mechanism = new Mechanism(mechanisms[m], new CkmRsaPkcsPssParams(hashes[h], mgfs[g], saltLength));

            if (h == m && g == m && saltLength == lengths[m])
            {
                bool expected = rsa.VerifyData(Data, signature, HashOf(hashes[m]), RSASignaturePadding.Pss);
                Assert.Equal(!tamper, expected);
                Assert.Equal(expected, key.Verify(mechanism, Data, signature));
                verified++;
            }
            else
            {
                var ex = Assert.Throws<Pkcs11MechanismException>(() => key.Verify(mechanism, Data, signature));
                Assert.Equal(CKR.CKR_MECHANISM_PARAM_INVALID, ex.ReturnValue);
                refused++;
            }
        }, iter: 200, threads: 1);

        // Both outcomes were drawn, so the property checked each of them.
        Assert.True(verified > 0, "No case had the BCL's profile.");
        Assert.True(refused > 0, "No case had other parameters.");
    }

    // === Mechanism values wider than 32 bits =================================
    // CK_ULONG is 64 bits on LP64 platforms, so a vendor mechanism value can exceed what CKM (a uint
    // enum) holds. The fallback must reject such a value with its NotSupportedException, not overflow
    // while mapping it. Only reachable when CK_ULONG is 64 bits.

    public static bool NativeULongIs64Bit => UnmanagedMemory.NativeULongSize == sizeof(ulong);

    private const CKM WideVendorMechanism = (CKM)0x1_8000_0001UL;

    [Fact(SkipUnless = nameof(NativeULongIs64Bit), Skip = "CK_ULONG is 32 bits on this platform")]
    public void ManagedFallback_RsaKey_WideVendorMechanism_IsNotSupported()
    {
        using var rsa = RSA.Create(2048);
        using var fake = PrivateOnlyRsaKey(rsa.ExportParameters(false), Mechanics);
        Pkcs11Key key = fake;

        Assert.Throws<NotSupportedException>(
            () => key.Verify(new Mechanism(WideVendorMechanism), Data, new byte[256]));
    }

    [Fact(SkipUnless = nameof(NativeULongIs64Bit), Skip = "CK_ULONG is 32 bits on this platform")]
    public void ManagedFallback_EcKey_WideVendorMechanism_IsNotSupported()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters pub = ec.ExportParameters(includePrivateParameters: false);
        using var fake = FakeKeys.Create(CKK.CKK_EC, ca => ca switch
        {
            CKA.CKA_EC_POINT => (CKR.CKR_OK, EncodeEcPoint(pub.Q)),
            CKA.CKA_EC_PARAMS => (CKR.CKR_OK, Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        }, Mechanics);
        Pkcs11Key key = fake;

        Assert.Throws<NotSupportedException>(
            () => key.Verify(new Mechanism(WideVendorMechanism), Data, new byte[64]));
    }

    [Fact(SkipUnless = nameof(NativeULongIs64Bit), Skip = "CK_ULONG is 32 bits on this platform")]
    public void SupportsMechanism_WideVendorMechanism_IsFalse()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var key = session.GenerateEcSigningKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);

        // CKM_SHA256 is on the managed token's mechanism list: the positive control that the probe works.
        Assert.True(key.SupportsMechanism(CKM.CKM_SHA256));
        Assert.False(key.SupportsMechanism(WideVendorMechanism));
    }
}
