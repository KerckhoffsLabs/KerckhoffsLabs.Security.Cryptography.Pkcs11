using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using BclECCurve = System.Security.Cryptography.ECCurve;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// ECDsaPkcs11 over the in-process <c>ManagedSoftToken</c>. Mirrors the SoftHSM suite: generate an EC
/// key pair on the token (C_GenerateKeyPair, EC), sign + verify on-token, tamper-reject, export the
/// public point (CKA_EC_POINT) and cross-verify the token's raw r‖s signature in the BCL.
/// </summary>
/// <remarks>
/// The managed token's mechanism list (see <c>ManagedSoftToken.C_GetMechanismList</c>) does NOT advertise
/// the combined CKM_ECDSA_SHA* mechanisms, so <c>SupportsMechanism</c> returns false and the adapter takes
/// its fallback path: hash managed-side, then sign/verify with raw CKM_ECDSA (which the token implements).
/// This exercises the same external behaviour as SoftHSM while driving the adapter's degraded path.
/// ECDsa is always available on supported platforms, so the crypto cases are plain [Fact]/[Theory].
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class ECDsaPkcs11Tests_Managed
{
    // Curve under test -> (library Pkcs11ECCurve to generate, curve-matched hash, expected exported OID value).
    private static (Pkcs11ECCurve curve, HashAlgorithmName hash, string? expectedOidValue) Spec(string curve) => curve switch
    {
        "P-256" => (Pkcs11ECCurve.NamedCurves.NistP256, HashAlgorithmName.SHA256, BclECCurve.NamedCurves.nistP256.Oid.Value),
        "P-384" => (Pkcs11ECCurve.NamedCurves.NistP384, HashAlgorithmName.SHA384, BclECCurve.NamedCurves.nistP384.Oid.Value),
        "P-521" => (Pkcs11ECCurve.NamedCurves.NistP521, HashAlgorithmName.SHA512, BclECCurve.NamedCurves.nistP521.Oid.Value),
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unknown EC curve."),
    };

    private static byte[] Digest(HashAlgorithmName hash, byte[] data) => hash.Name switch
    {
        "SHA256" => SHA256.HashData(data),
        "SHA384" => SHA384.HashData(data),
        "SHA512" => SHA512.HashData(data),
        _ => throw new ArgumentOutOfRangeException(nameof(hash), hash.Name, "Unexpected hash."),
    };

    // Generates an EC key pair for the curve, wraps it as ECDsaPkcs11, runs the body with the
    // adapter and the curve-matched hash.
    private static void WithEcDsa(string curve, Action<ECDsaPkcs11, HashAlgorithmName> body)
    {
        var (_, hash, _) = Spec(curve);
        WithEcDsa(curve, (_, ec) => body(ec, hash));
    }

    // As above, but hands the session to the body (for scoping to the AllowInsecure policy) and leaves the hash to
    // the caller — so the same key can be exercised across hash algorithms independent of the curve.
    private static void WithEcDsa(string curve, Action<Pkcs11Session, ECDsaPkcs11> body, ManagedSoftToken? token = null)
    {
        var (eccurve, _, _) = Spec(curve);
        using var library = (token ?? new ManagedSoftToken()).Load();
        using var session = ManagedToken.OpenSession(library);
        using var key = session.GenerateEcKeyPair(eccurve);
        using var ec = new ECDsaPkcs11(key);
        body(session, ec);
    }

    // === Construction =====================================================

    [Fact]
    public void Ctor_NonEcKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("aes").ValueLen(32).Encrypt().Decrypt().Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new ECDsaPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }

    // === Sign/verify data — byte[] overloads (BCL hashes managed-side, then SignHash) =======

    // Curve × hash matrix: ECDSA signs whatever digest it is handed, so the curve and the
    // message-digest algorithm are independent. Exercise the full cross-product (every NIST curve
    // against SHA-256/384/512) rather than only each curve's "matched" hash, and cross-verify each
    // signature under the BCL from the exported public key (CKM_ECDSA emits raw r‖s = IEEE P1363).
    // SHA-1 requires the AllowInsecure policy and has its own gating tests below.
    [Theory]
    [InlineData("P-256", "SHA256")]
    [InlineData("P-256", "SHA384")]
    [InlineData("P-256", "SHA512")]
    [InlineData("P-384", "SHA256")]
    [InlineData("P-384", "SHA384")]
    [InlineData("P-384", "SHA512")]
    [InlineData("P-521", "SHA256")]
    [InlineData("P-521", "SHA384")]
    [InlineData("P-521", "SHA512")]
    public void SignVerifyData_CurveHashMatrix_RoundTrips(string curve, string hashName) => WithEcDsa(curve, (_, ec) =>
    {
        var hash = new HashAlgorithmName(hashName);
        byte[] data = Encoding.UTF8.GetBytes($"ecdsa {curve}/{hashName}");
        byte[] sig = ec.SignData(data, hash);
        Assert.True(ec.VerifyData(data, sig, hash));

        using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));
        Assert.True(bcl.VerifyData(data, sig, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        byte[] tampered = [.. data];
        tampered[0] ^= 0xFF;
        Assert.False(ec.VerifyData(tampered, sig, hash));
    });

    // === Sign/verify data — span overloads (TrySignData / VerifyData(span)) ================

    [Theory]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void TrySignData_Span_VerifyData_Span_RoundTrips(string curve) => WithEcDsa(curve, (ec, hash) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("combined hash+sign on token");
        byte[] dest = new byte[256];

        Assert.True(ec.TrySignData(data, dest, hash, out int written));
        Assert.True(written > 0);

        var sig = dest.AsSpan(0, written);
        Assert.True(ec.VerifyData(data.AsSpan(), sig, hash));

        byte[] tampered = [.. data];
        tampered[0] ^= 0xFF;
        Assert.False(ec.VerifyData(tampered.AsSpan(), sig, hash));
    });

    [Fact]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => WithEcDsa("P-256", (ec, hash) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("too small destination");
        Assert.False(ec.TrySignData(data, new byte[1], hash, out int written));
        Assert.Equal(0, written);
    });

    // A P-256 signature in the IEEE P1363 format is exactly 64 bytes, so a 64-byte destination is enough.
    [Fact]
    public void TrySignData_DestinationOfExactlyTheSignatureSize_Succeeds() => WithEcDsa("P-256", (ec, hash) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("exact destination");
        byte[] destination = new byte[64];

        Assert.True(ec.TrySignData(data, destination, hash, out int written));

        Assert.Equal(64, written);
        Assert.True(ec.VerifyData(data, destination, hash));
    });

    // A signature with a flipped byte must not verify (signature authenticity, not just message).
    [Theory]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void VerifyData_TamperedSignature_ReturnsFalse(string curve) => WithEcDsa(curve, (ec, hash) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("tamper the signature");
        byte[] sig = ec.SignData(data, hash);
        sig[0] ^= 0xFF;
        Assert.False(ec.VerifyData(data, sig, hash));
    });

    // === SHA-1 gating: the managed-side hash fallback is refused unless the AllowInsecure policy applies ===========
    // Mirrors the session's crypto policy check rejecting the combined CKM_ECDSA_SHA1 mechanism, so
    // SHA-1 signing is gated the same way regardless of whether the token exposes CKM_ECDSA_SHA1 natively.

    [Fact]
    public void SignData_Sha1_GatedByDefault_Throws() => WithEcDsa("P-256", (_, ec) =>
        Assert.Throws<CryptoPolicyViolationException>(
            () => ec.SignData(Encoding.UTF8.GetBytes("legacy"), HashAlgorithmName.SHA1)));

    [Fact]
    public void SignData_Stream_Sha1_GatedByDefault_Throws() => WithEcDsa("P-256", (_, ec) =>
    {
        using var data = new MemoryStream(Encoding.UTF8.GetBytes("legacy"));
#pragma warning disable KLPKCS11010 // SHA-1 signing is the refusal under test
        Assert.Throws<CryptoPolicyViolationException>(() => ec.SignData(data, HashAlgorithmName.SHA1));
#pragma warning restore KLPKCS11010
    });

    [Fact]
    public void VerifyData_Sha1_GatedByDefault_Throws() => WithEcDsa("P-256", (session, ec) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("legacy");
        byte[] sig;
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            sig = ec.SignData(data, HashAlgorithmName.SHA1);

        Assert.Throws<CryptoPolicyViolationException>(
            () => ec.VerifyData(data, sig, HashAlgorithmName.SHA1));
    });

    [Fact]
    public void SignVerifyData_Sha1_AllowInsecure_RoundTrips() => WithEcDsa("P-256", (session, ec) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("legacy");
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            byte[] sig = ec.SignData(data, HashAlgorithmName.SHA1);
            Assert.True(ec.VerifyData(data, sig, HashAlgorithmName.SHA1));
        }
    });

    // === SHA-1 under NistApproved: legacy verification allowed, signing refused ===
    // NistApproved allows the SHA-1 hash only for Verify (SP 800-131A legacy use). Every BCL verification
    // entry point must report its own direction to the policy, so a legacy signature verifies through
    // whichever overload the caller picks. The signature is made over a managed SHA-1 digest with
    // SignHash (raw CKM_ECDSA, which carries no hash choice), because NistApproved refuses SHA-1 SignData.

    private static void WithNistApprovedEcDsa(Action<ECDsaPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library, CryptoPolicy.NistApproved);
        using var key = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var ec = new ECDsaPkcs11(key);
        body(ec);
    }

    private static readonly byte[] LegacyData = Encoding.UTF8.GetBytes("legacy signature, verified under NistApproved");

    public static TheoryData<string> Sha1VerifyEntryPoints() =>
    [
        "byte[]", "byte[] range", "Stream", "span", "byte[] + DER", "span + DER", "Stream + DER",
    ];

    [Theory]
    [MemberData(nameof(Sha1VerifyEntryPoints))]
    public void VerifyData_Sha1_UnderNistApproved_VerifiesALegacySignature(string entryPoint) => WithNistApprovedEcDsa(ec =>
    {
        byte[] digest = SHA1.HashData(LegacyData);
        byte[] p1363 = ec.SignHash(digest);
        byte[] der = ec.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence);
        HashAlgorithmName sha1 = HashAlgorithmName.SHA1;
        using var stream = new MemoryStream(LegacyData);

        bool verified = entryPoint switch
        {
            "byte[]" => ec.VerifyData(LegacyData, p1363, sha1),
            "byte[] range" => ec.VerifyData(LegacyData, 0, LegacyData.Length, p1363, sha1),
            "Stream" => ec.VerifyData(stream, p1363, sha1),
            "span" => ec.VerifyData(LegacyData.AsSpan(), p1363.AsSpan(), sha1),
            "byte[] + DER" => ec.VerifyData(LegacyData, der, sha1, DSASignatureFormat.Rfc3279DerSequence),
            "span + DER" => ec.VerifyData(LegacyData.AsSpan(), der.AsSpan(), sha1, DSASignatureFormat.Rfc3279DerSequence),
            "Stream + DER" => ec.VerifyData(stream, der, sha1, DSASignatureFormat.Rfc3279DerSequence),
            _ => throw new ArgumentOutOfRangeException(nameof(entryPoint)),
        };

        Assert.True(verified);
    });

    [Theory]
    [MemberData(nameof(Sha1VerifyEntryPoints))]
    public void VerifyData_Sha1_UnderRecommended_IsStillRefused(string entryPoint) => WithEcDsa("P-256", (_, ec) =>
    {
        byte[] signature = new byte[64];
        HashAlgorithmName sha1 = HashAlgorithmName.SHA1;
        using var stream = new MemoryStream(LegacyData);
        Action verify = entryPoint switch
        {
            "byte[]" => () => ec.VerifyData(LegacyData, signature, sha1),
            "byte[] range" => () => ec.VerifyData(LegacyData, 0, LegacyData.Length, signature, sha1),
            "Stream" => () => ec.VerifyData(stream, signature, sha1),
            "span" => () => ec.VerifyData(LegacyData.AsSpan(), signature.AsSpan(), sha1),
            "byte[] + DER" => () => ec.VerifyData(LegacyData, signature, sha1, DSASignatureFormat.Rfc3279DerSequence),
            "span + DER" => () => ec.VerifyData(LegacyData.AsSpan(), signature.AsSpan(), sha1, DSASignatureFormat.Rfc3279DerSequence),
            "Stream + DER" => () => ec.VerifyData(stream, signature, sha1, DSASignatureFormat.Rfc3279DerSequence),
            _ => throw new ArgumentOutOfRangeException(nameof(entryPoint)),
        };

        Assert.Throws<CryptoPolicyViolationException>(verify);
    });

    [Fact]
    public void SignData_Sha1_UnderNistApproved_IsRefusedOnEveryEntryPoint() => WithNistApprovedEcDsa(ec =>
    {
        HashAlgorithmName sha1 = HashAlgorithmName.SHA1;
        using var stream = new MemoryStream(LegacyData);
        using var derStream = new MemoryStream(LegacyData);
        Assert.Throws<CryptoPolicyViolationException>(() => ec.SignData(LegacyData, sha1));
        Assert.Throws<CryptoPolicyViolationException>(() => ec.SignData(stream, sha1));
        Assert.Throws<CryptoPolicyViolationException>(() => ec.SignData(LegacyData.AsSpan(), sha1));
        Assert.Throws<CryptoPolicyViolationException>(() => ec.SignData(LegacyData, sha1, DSASignatureFormat.Rfc3279DerSequence));
        Assert.Throws<CryptoPolicyViolationException>(() => ec.SignData(derStream, sha1, DSASignatureFormat.Rfc3279DerSequence));
    });

    // The Stream signing overloads now hash for themselves; they must still produce signatures that verify.
    [Fact]
    public void SignData_Stream_Sha256_RoundTripsInBothFormats() => WithNistApprovedEcDsa(ec =>
    {
        HashAlgorithmName sha256 = HashAlgorithmName.SHA256;
        using var stream = new MemoryStream(LegacyData);
        using var derStream = new MemoryStream(LegacyData);
        byte[] p1363 = ec.SignData(stream, sha256);
        byte[] der = ec.SignData(derStream, sha256, DSASignatureFormat.Rfc3279DerSequence);
        Assert.True(ec.VerifyData(LegacyData, p1363, sha256));
        Assert.True(ec.VerifyData(LegacyData, der, sha256, DSASignatureFormat.Rfc3279DerSequence));
    });

    // The overloads this class overrides validate the hash name the way the BCL does, naming the parameter.
    [Fact]
    public void OverriddenOverloads_EmptyHashName_ThrowArgumentExceptionNamingHashAlgorithm() => WithNistApprovedEcDsa(ec =>
    {
        var empty = new HashAlgorithmName("");

        var verify = Assert.Throws<ArgumentException>(() => ec.VerifyData(LegacyData, 0, LegacyData.Length, new byte[64], empty));
        Assert.Equal("hashAlgorithm", verify.ParamName);

        using var stream = new MemoryStream(LegacyData);
        var sign = Assert.Throws<ArgumentException>(() => ec.SignData(stream, empty));
        Assert.Equal("hashAlgorithm", sign.ParamName);
    });

    // Argument errors come first, as the BCL reports them. SHA-1 is refused by the default policy, so a
    // check that did not run would surface as a policy refusal instead.
    [Fact]
    public void OverriddenOverloads_ArgumentErrors_AreReportedBeforeThePolicy() => WithEcDsa("P-256", (_, ec) =>
    {
        byte[] data = new byte[8];
        byte[] sig = new byte[64];
        var sha1 = HashAlgorithmName.SHA1;

#pragma warning disable KLPKCS11010 // SHA-1 only makes the policy refuse what gets past the argument checks
        Assert.Equal("data", Assert.Throws<ArgumentNullException>(() => ec.VerifyData(null!, 0, 0, sig, sha1)).ParamName);
        Assert.Equal("offset", Assert.Throws<ArgumentOutOfRangeException>(() => ec.VerifyData(data, -1, 0, sig, sha1)).ParamName);
        Assert.Equal("offset", Assert.Throws<ArgumentOutOfRangeException>(() => ec.VerifyData(data, 9, 0, sig, sha1)).ParamName);
        Assert.Equal("count", Assert.Throws<ArgumentOutOfRangeException>(() => ec.VerifyData(data, 0, -1, sig, sha1)).ParamName);
        Assert.Equal("count", Assert.Throws<ArgumentOutOfRangeException>(() => ec.VerifyData(data, 4, 5, sig, sha1)).ParamName);
        Assert.Equal("signature", Assert.Throws<ArgumentNullException>(() => ec.VerifyData(data, 0, 8, null!, sha1)).ParamName);
        Assert.Equal("data", Assert.Throws<ArgumentNullException>(() => ec.SignData((Stream)null!, sha1)).ParamName);
#pragma warning restore KLPKCS11010
    });

    // === Sign/verify hash — raw ECDSA, no on-token hashing ==================

    [Fact]
    public void SignHash_VerifyHash_RoundTrips() => WithEcDsa("P-256", (ec, _) =>
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("raw ecdsa over a digest"));
        byte[] sig = ec.SignHash(hash);
        Assert.True(ec.VerifyHash(hash, sig));

        hash[0] ^= 0xFF;
        Assert.False(ec.VerifyHash(hash, sig));
    });

    [Fact]
    public void SignHash_NullHash_Throws() => WithEcDsa("P-256", (ec, _) =>
        Assert.Throws<ArgumentNullException>(() => ec.SignHash(null!)));

    [Fact]
    public void VerifyHash_NullArguments_Throw() => WithEcDsa("P-256", (ec, _) =>
    {
        Assert.Throws<ArgumentNullException>(() => ec.VerifyHash(null!, new byte[64]));
        Assert.Throws<ArgumentNullException>(() => ec.VerifyHash(new byte[32], null!));
    });

    // === Key material export ==============================================

    [Theory]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint(string curve)
    {
        var (_, _, expectedOidValue) = Spec(curve);
        WithEcDsa(curve, (ec, _) =>
        {
            var p = ec.ExportParameters(includePrivateParameters: false);
            Assert.Equal(expectedOidValue, p.Curve.Oid.Value);
            Assert.NotNull(p.Q.X);
            Assert.NotNull(p.Q.Y);
            Assert.Null(p.D); // private parts must not be set
        });
    }

    // cross-library verification. Export the public key, rebuild an ECDsa from it, and verify the
    // PKCS#11 signature with the BCL — catches a wrong named-curve OID or a mangled point in
    // ExportParameters that a same-instance round-trip would not. CKM_ECDSA emits raw r||s, so the
    // BCL must interpret the signature as IEEE P1363.
    [Theory]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void SignData_VerifiesUnderBclFromExportedPublicKey(string curve) => WithEcDsa(curve, (ec, hash) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("cross-library verify");
        byte[] sig = ec.SignData(data, hash);

        using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));
        Assert.True(bcl.VerifyData(data, sig, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    });

    // SignHash path: the token's raw r||s signature over an externally computed digest must verify in
    // the BCL under the exported public point.
    [Theory]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void SignHash_VerifiesUnderBclFromExportedPublicKey(string curve) => WithEcDsa(curve, (ec, hash) =>
    {
        byte[] digest = Digest(hash, Encoding.UTF8.GetBytes("digest cross-verify"));
        byte[] sig = ec.SignHash(digest);

        using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));
        Assert.True(bcl.VerifyHash(digest, sig, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    });

    [Fact]
    public void ExportParameters_Private_ThrowsInsecure() => WithEcDsa("P-256", (ec, _) =>
        Assert.Throws<CryptoPolicyViolationException>(() => ec.ExportParameters(includePrivateParameters: true)));

    // === Unsupported BCL surface (PKCS#11 keys are token-resident / non-extractable) ========

    [Fact]
    public void ExportExplicitParameters_Throws() => WithEcDsa("P-256", (ec, _) =>
        Assert.Throws<NotSupportedException>(() => ec.ExportExplicitParameters(includePrivateParameters: false)));

    [Fact]
    public void ImportParameters_Throws() => WithEcDsa("P-256", (ec, _) =>
        Assert.Throws<NotSupportedException>(() => ec.ImportParameters(default)));

    [Fact]
    public void GenerateKey_Throws() => WithEcDsa("P-256", (ec, _) =>
        Assert.Throws<NotSupportedException>(() => ec.GenerateKey(BclECCurve.NamedCurves.nistP256)));

    // === KeySize / LegalKeySizes / DER-format signing =======================
    // Regression coverage for the adapter never assigning KeySizeValue: KeySize was 0,
    // LegalKeySizes threw NullReferenceException, and GetMaxSignatureSize/SignData with
    // DSASignatureFormat.Rfc3279DerSequence — the format X509SignatureGenerator.CreateForECDsa uses —
    // both threw NotSupportedException, making token-backed CSR/certificate signing impossible.

    [Theory]
    [InlineData("P-256", 256)]
    [InlineData("P-384", 384)]
    [InlineData("P-521", 521)]
    public void KeySize_ReflectsTokenCurve(string curve, int expectedBits) => WithEcDsa(curve, (ec, _) =>
        Assert.Equal(expectedBits, ec.KeySize));

    [Theory]
    [InlineData("P-256", 256)]
    [InlineData("P-384", 384)]
    [InlineData("P-521", 521)]
    public void LegalKeySizes_ReflectsTokenCurve(string curve, int expectedBits) => WithEcDsa(curve, (ec, _) =>
    {
        KeySizes[] sizes = ec.LegalKeySizes;
        KeySizes only = Assert.Single(sizes);
        Assert.Equal(expectedBits, only.MinSize);
        Assert.Equal(expectedBits, only.MaxSize);
    });

    [Theory]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void SignData_Rfc3279DerSequenceFormat_RoundTrips(string curve) => WithEcDsa(curve, (ec, hash) =>
    {
        byte[] data = Encoding.UTF8.GetBytes($"der-format signature {curve}");

        int maxSize = ec.GetMaxSignatureSize(DSASignatureFormat.Rfc3279DerSequence);
        Assert.True(maxSize > 0);

        byte[] sig = ec.SignData(data, hash, DSASignatureFormat.Rfc3279DerSequence);
        Assert.True(sig.Length <= maxSize);
        Assert.True(ec.VerifyData(data, sig, hash, DSASignatureFormat.Rfc3279DerSequence));

        using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));
        Assert.True(bcl.VerifyData(data, sig, hash, DSASignatureFormat.Rfc3279DerSequence));
    });

    // Token-backed CSR signing: CertificateRequest.Create uses X509SignatureGenerator.CreateForECDsa,
    // which signs with DSASignatureFormat.Rfc3279DerSequence.
    [Fact]
    public void CertificateRequest_Create_SigningRequest_Succeeds() => WithEcDsa("P-256", (ec, hash) =>
    {
        var req = new CertificateRequest("CN=pkcs11-test", ec, hash);
        byte[] csr = req.CreateSigningRequest();
        Assert.NotEmpty(csr);
    });

    // A real token can't be coaxed into failing to read CKA_EC_PARAMS — it's a required attribute of
    // every EC key object — so this drives the fallback's error path via a fake library.
    [Fact]
    public void KeySize_EcParamsAttributeFails_StaysAtBclDefault()
    {
        using var key = FakeKeys.Create(CKK.CKK_EC, _ => (CKR.CKR_DEVICE_ERROR, null));
        using var ec = new ECDsaPkcs11(key);
        Assert.Equal(0, ec.KeySize);
    }

    // CKA_EC_PARAMS readable but not a DER-encoded named-curve OID: Pkcs11ECCurve.FromEcParams
    // throws ArgumentException, which the fallback must also treat as "unknown, leave default".
    [Fact]
    public void KeySize_EcParamsNotAValidOid_StaysAtBclDefault()
    {
        using var key = FakeKeys.Create(CKK.CKK_EC, _ => (CKR.CKR_OK, (byte[])[0xFF, 0xFF, 0xFF]));
        using var ec = new ECDsaPkcs11(key);
        Assert.Equal(0, ec.KeySize);
    }

    // === SHA-3 and SHA-224 in the span overloads' fallback hasher ==================================
    // The token lists no combined CKM_ECDSA_* mechanism, so TrySignData and VerifyData(span) hash before
    // raw CKM_ECDSA: SHA-3 with the BCL's, SHA-224 with the token's CKM_SHA224 digest when it has one.

    private static readonly HashAlgorithmName Sha224 = new("SHA224");

    // The managed token's SHA-224. The BCL has none to give it, so this is a stand-in: whatever it computes,
    // a signature the adapter makes over SHA-224 is a signature over it.
    private static byte[] StandInSha224(byte[] data) => SHA256.HashData(data)[..28];

    private static byte[] TrySign(ECDsaPkcs11 ec, byte[] data, HashAlgorithmName hash)
    {
        byte[] destination = new byte[256];
        Assert.True(ec.TrySignData(data, destination, hash, out int written));
        return destination[..written];
    }

    public static TheoryData<string> Sha3Hashes() => ["SHA3-256", "SHA3-384", "SHA3-512"];

    private static byte[] Sha3(string hashName, byte[] data) => hashName switch
    {
        "SHA3-256" => SHA3_256.HashData(data),
        "SHA3-384" => SHA3_384.HashData(data),
        _ => SHA3_512.HashData(data),
    };

    [Theory]
    [MemberData(nameof(Sha3Hashes))]
    public void SpanOverloads_Sha3_HashWithTheBcl(string hashName)
    {
        Assert.SkipUnless(SHA3_256.IsSupported, "The host BCL has no SHA-3.");
        WithEcDsa("P-256", (_, ec) =>
        {
            var hash = new HashAlgorithmName(hashName);
            byte[] data = Encoding.UTF8.GetBytes($"span overloads over {hashName}");
            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));

            Assert.True(bcl.VerifyHash(Sha3(hashName, data), TrySign(ec, data, hash)));

            byte[] sig = ec.SignHash(Sha3(hashName, data));
            Assert.True(ec.VerifyData(data.AsSpan(), sig, hash));
            Assert.False(ec.VerifyData(tampered.AsSpan(), sig, hash));
        });
    }

    [Fact]
    public void SpanOverloads_Sha224_HashWithTheTokensDigest() => WithEcDsa("P-256", (session, ec) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("span overloads over the token's SHA-224");
        byte[] tampered = [.. data];
        tampered[0] ^= 0xFF;
        using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));
        using var policy = session.UsePolicy(CryptoPolicy.AllowInsecure);

        Assert.True(bcl.VerifyHash(StandInSha224(data), TrySign(ec, data, Sha224)));

        byte[] sig = ec.SignHash(StandInSha224(data));
        Assert.True(ec.VerifyData(data.AsSpan(), sig, Sha224));
        Assert.False(ec.VerifyData(tampered.AsSpan(), sig, Sha224));
    }, token: new ManagedSoftToken { Sha224Digest = StandInSha224 });

    // The hash is put to the session's policy before the token digests anything, as for every other hash.
    [Fact]
    public void SpanOverloads_Sha224_GatedByDefault_ThrowsBeforeTheTokenDigests()
    {
        int digests = 0;
        var token = new ManagedSoftToken { Sha224Digest = data => { digests++; return StandInSha224(data); } };
        WithEcDsa("P-256", (_, ec) =>
        {
            Assert.IsType<HashUseRequest>(Assert.Throws<CryptoPolicyViolationException>(
                () => ec.TrySignData(LegacyData, new byte[256], Sha224, out int _)).Request);
            Assert.IsType<HashUseRequest>(Assert.Throws<CryptoPolicyViolationException>(
                () => ec.VerifyData(LegacyData.AsSpan(), new byte[64], Sha224)).Request);
        }, token: token);
        Assert.Equal(0, digests);
    }

    // With neither CKM_ECDSA_SHA224 nor the CKM_SHA224 digest, SHA-224 has no hash to sign over.
    [Fact]
    public void SpanOverloads_Sha224_WithoutTheTokensDigest_ThrowNotSupported() => WithEcDsa("P-256", (session, ec) =>
    {
        using var policy = session.UsePolicy(CryptoPolicy.AllowInsecure);
        Assert.Throws<NotSupportedException>(() => ec.TrySignData(LegacyData, new byte[256], Sha224, out int _));
        Assert.Throws<NotSupportedException>(() => ec.VerifyData(LegacyData.AsSpan(), new byte[64], Sha224));
    });

    // === A curve outside the library's catalog ==============================================
    // prime239v1 (X9.62) is outside the built-in catalog. Available wherever the BCL's backend implements it
    // (OpenSSL does; CNG does not).
    private const string Prime239v1Oid = "1.2.840.10045.3.1.4";

    public static bool Prime239v1Supported { get; } = ProbeCurve(Prime239v1Oid);

    private static bool ProbeCurve(string oid)
    {
        try
        {
            using (ECDsa.Create(BclECCurve.CreateFromValue(oid))) { }
            return true;
        }
        catch (PlatformNotSupportedException) { return false; }
        catch (CryptographicException) { return false; }
    }

    // AllowInsecure: the default policy refuses a key on a curve it doesn't list.
    private static void WithPrime239v1(Pkcs11CurveCatalog? catalog, Action<ECDsaPkcs11> body)
    {
        using var library = new ManagedSoftToken().Load(new Pkcs11LibraryOptions { CurveCatalog = catalog });
        using var session = ManagedToken.OpenSession(library);
        using IDisposable insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using var key = session.GenerateEcKeyPair(Pkcs11ECCurve.CreateFromValue(Prime239v1Oid));
        using var ec = new ECDsaPkcs11(key);
        body(ec);
    }

    // The token's r‖s signature re-encoded as DER, independently of the adapter.
    private static byte[] ToDer(byte[] ieee)
    {
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(Minimal(ieee.AsSpan(0, ieee.Length / 2)));
            writer.WriteIntegerUnsigned(Minimal(ieee.AsSpan(ieee.Length / 2)));
        }
        return writer.Encode();

        static ReadOnlySpan<byte> Minimal(ReadOnlySpan<byte> value)
        {
            int i = value.IndexOfAnyExcept((byte)0);
            return i < 0 ? value[^1..] : value[i..];
        }
    }

    // Without the curve in the catalog, KeySize stays 0 and neither the field nor the order size is known, so
    // a DER signature can't be converted for the token: it does not verify, as the BCL's own conversion
    // returns false when it can't size a signature.
    [Fact(SkipUnless = nameof(Prime239v1Supported), Skip = "Requires " + nameof(Prime239v1Supported))]
    public void VerifyHash_DerSignature_CurveOutsideTheCatalog_ReturnsFalse() => WithPrime239v1(null, ec =>
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("prime239v1"));
        byte[] ieee = ec.SignHash(hash);

        Assert.Equal(0, ec.KeySize);
        Assert.True(ec.VerifyHash(hash, ieee));
        Assert.False(ec.VerifyHash(hash, ToDer(ieee), DSASignatureFormat.Rfc3279DerSequence));
    });

    // r = 0 and s = 0 (Wycheproof's "special case values" signature): the base class's conversion sized
    // to zero bytes and threw IndexOutOfRangeException on the single zero byte of each INTEGER.
    [Fact(SkipUnless = nameof(Prime239v1Supported), Skip = "Requires " + nameof(Prime239v1Supported))]
    public void VerifyHash_DerZeroSignature_CurveOutsideTheCatalog_ReturnsFalse() => WithPrime239v1(null, ec =>
    {
        byte[] der = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        byte[] data = Encoding.UTF8.GetBytes("123400");

        Assert.False(ec.VerifyHash(SHA256.HashData(data), der, DSASignatureFormat.Rfc3279DerSequence));
        Assert.False(ec.VerifyData(data, der, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
    });

    [Fact(SkipUnless = nameof(Prime239v1Supported), Skip = "Requires " + nameof(Prime239v1Supported))]
    public void VerifyHash_DerSignature_CurveInTheLibraryCatalog_Verifies() =>
        WithPrime239v1(Pkcs11CurveCatalog.Default.With(new Pkcs11CurveInfo(Prime239v1Oid, "prime239v1", 239)), ec =>
        {
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("prime239v1"));
            byte[] der = ToDer(ec.SignHash(hash));

            Assert.Equal(239, ec.KeySize);
            Assert.True(ec.VerifyHash(hash, der, DSASignatureFormat.Rfc3279DerSequence));
        });

    // === The IEEE P1363 length is the order's ===============================================
    // secp224k1's order is 225 bits, so r‖s is 58 bytes while KeySize is 224. The fake module refuses
    // C_VerifyInit, so a signature that reaches the token throws; one of the wrong length returns false first.
    [Theory]
    [InlineData(56)]
    [InlineData(57)]
    [InlineData(59)]
    public void VerifyHash_P1363_Secp224k1_LengthIsTheOrders(int wrongLength)
    {
        Assert.True(Pkcs11CurveCatalog.Default.TryGetByName("secp224k1", out Pkcs11CurveInfo? info));
        byte[] ecParams = info.ToCurve().GetEcParams();
        using var key = FakeKeys.Create(CKK.CKK_EC, ca => ca == CKA.CKA_EC_PARAMS
            ? (CKR.CKR_OK, ecParams)
            : (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null), CryptoPolicy.AllowInsecure, publicOnly: true);
        using var ec = new ECDsaPkcs11(key);
        Assert.Equal(224, ec.KeySize);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => ec.VerifyHash(new byte[32], new byte[58]));
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
        Assert.False(ec.VerifyHash(new byte[32], new byte[wrongLength]));
        Assert.False(ec.VerifyData(new byte[3].AsSpan(), new byte[wrongLength], HashAlgorithmName.SHA256));
    }
}
