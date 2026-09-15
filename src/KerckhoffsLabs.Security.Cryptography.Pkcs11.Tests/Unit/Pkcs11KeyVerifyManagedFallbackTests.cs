using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// CKM_RSA_PKCS is used deliberately here to hit MapRsaSignMechanism's "no managed equivalent" arm
// (raw RSA carries its hash inside a DigestInfo, not at the mechanism level) — mechanism security is
// not what this test pins, so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11008

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
public sealed class Pkcs11KeyVerifyManagedFallbackTests
{
    private static readonly byte[] Data = Encoding.UTF8.GetBytes("verify via synthesized public key");

    // === RSA =================================================================

    public static TheoryData<CKM, HashAlgorithmName, RSASignaturePadding> RsaMechanisms() =>
        new()
        {
            { CKM.CKM_SHA1_RSA_PKCS, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1 },
            { CKM.CKM_SHA256_RSA_PKCS, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1 },
            { CKM.CKM_SHA384_RSA_PKCS, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1 },
            { CKM.CKM_SHA512_RSA_PKCS, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1 },
            { CKM.CKM_SHA1_RSA_PKCS_PSS, HashAlgorithmName.SHA1, RSASignaturePadding.Pss },
            { CKM.CKM_SHA256_RSA_PKCS_PSS, HashAlgorithmName.SHA256, RSASignaturePadding.Pss },
            { CKM.CKM_SHA384_RSA_PKCS_PSS, HashAlgorithmName.SHA384, RSASignaturePadding.Pss },
            { CKM.CKM_SHA512_RSA_PKCS_PSS, HashAlgorithmName.SHA512, RSASignaturePadding.Pss },
        };

    [Theory]
    [MemberData(nameof(RsaMechanisms))]
    public void Verify_PrivateOnlyRsaKey_SynthesizesPublicKeyAndVerifies(
        CKM mechanismType, HashAlgorithmName hash, RSASignaturePadding padding)
    {
        using var rsa = RSA.Create(2048);
        RSAParameters pub = rsa.ExportParameters(includePrivateParameters: false);
        byte[] signature = rsa.SignData(Data, hash, padding);

        using var key = FakeKeys.Create(CKK.CKK_RSA, ca => ca switch
        {
            CKA.CKA_MODULUS => (CKR.CKR_OK, pub.Modulus),
            CKA.CKA_PUBLIC_EXPONENT => (CKR.CKR_OK, pub.Exponent),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        });

        Assert.True(key.Verify(new Mechanism(mechanismType), Data, signature));

        byte[] tampered = [.. signature];
        tampered[0] ^= 0xFF;
        Assert.False(key.Verify(new Mechanism(mechanismType), Data, tampered));
    }

    [Fact]
    public void Verify_PrivateOnlyRsaKey_UnsupportedMechanism_Throws()
    {
        using var rsa = RSA.Create(2048);
        RSAParameters pub = rsa.ExportParameters(includePrivateParameters: false);

        using var key = FakeKeys.Create(CKK.CKK_RSA, ca => ca switch
        {
            CKA.CKA_MODULUS => (CKR.CKR_OK, pub.Modulus),
            CKA.CKA_PUBLIC_EXPONENT => (CKR.CKR_OK, pub.Exponent),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        });

        var ex = Assert.Throws<NotSupportedException>(
            () => key.Verify(new Mechanism(CKM.CKM_RSA_PKCS), Data, new byte[256]));
        Assert.Contains("Managed RSA verify is not implemented", ex.Message);
    }

    [Fact]
    public void Verify_PrivateOnlyRsaKey_AttributesSensitive_ThrowsHandleInvalid()
    {
        using var key = FakeKeys.Create(CKK.CKK_RSA, _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null));

        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => key.Verify(new Mechanism(CKM.CKM_SHA256_RSA_PKCS), Data, new byte[256]));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
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

        using var key = FakeKeys.Create(CKK.CKK_EC, ca => ca switch
        {
            CKA.CKA_EC_POINT => (CKR.CKR_OK, EncodeEcPoint(pub.Q)),
            CKA.CKA_EC_PARAMS => (CKR.CKR_OK, Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        });

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
    public void Verify_PrivateOnlyEcKey_CombinedMechanism_SynthesizesPublicKeyAndVerifies(
        CKM mechanismType, string hashName)
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters pub = ec.ExportParameters(includePrivateParameters: false);
        var hash = new HashAlgorithmName(hashName);
        byte[] signature = ec.SignData(Data, hash);

        using var key = FakeKeys.Create(CKK.CKK_EC, ca => ca switch
        {
            CKA.CKA_EC_POINT => (CKR.CKR_OK, EncodeEcPoint(pub.Q)),
            CKA.CKA_EC_PARAMS => (CKR.CKR_OK, Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        });

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

        using var key = FakeKeys.Create(CKK.CKK_EC, ca => ca switch
        {
            CKA.CKA_EC_POINT => (CKR.CKR_OK, EncodeEcPoint(pub.Q)),
            CKA.CKA_EC_PARAMS => (CKR.CKR_OK, Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()),
            _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
        });

        var ex = Assert.Throws<NotSupportedException>(
            () => key.Verify(new Mechanism(CKM.CKM_ECDSA_SHA224), Data, new byte[64]));
        Assert.Contains("Managed ECDSA verify is not implemented", ex.Message);
    }

    [Fact]
    public void Verify_PrivateOnlyEcKey_AttributesUnreadable_ThrowsHandleInvalid()
    {
        using var key = FakeKeys.Create(CKK.CKK_EC, _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null));

        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => key.Verify(new Mechanism(CKM.CKM_ECDSA_SHA256), Data, new byte[64]));
        Assert.Equal(CKR.CKR_OBJECT_HANDLE_INVALID, ex.ReturnValue);
    }
}
