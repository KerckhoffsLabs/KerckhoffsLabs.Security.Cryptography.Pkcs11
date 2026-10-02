using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using BclECCurve = System.Security.Cryptography.ECCurve;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

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
[NoBackendCollection("Drives a per-test ManagedSoftToken in process — no native module is loaded and " +
                     "the token holds no static state, so this is safe alongside every backend collection.")]
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

    // As above, but hands the workspace to the body (for scoping to the AllowInsecure policy) and leaves the hash to
    // the caller — so the same key can be exercised across hash algorithms independent of the curve.
    private static void WithEcDsa(string curve, Action<Pkcs11Workspace, ECDsaPkcs11> body)
    {
        var (eccurve, _, _) = Spec(curve);
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var key = workspace.GenerateEcKeyPair(eccurve);
        using var ec = new ECDsaPkcs11(key);
        body(workspace, ec);
    }

    // === Construction =====================================================

    [Fact]
    public void Ctor_NonEcKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("aes").ValueLen(32).Encrypt().Decrypt().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl);

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
    public void VerifyData_Sha1_GatedByDefault_Throws() => WithEcDsa("P-256", (workspace, ec) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("legacy");
        byte[] sig;
        using (workspace.UsePolicy(CryptoPolicy.AllowInsecure))
            sig = ec.SignData(data, HashAlgorithmName.SHA1);

        Assert.Throws<CryptoPolicyViolationException>(
            () => ec.VerifyData(data, sig, HashAlgorithmName.SHA1));
    });

    [Fact]
    public void SignVerifyData_Sha1_AllowInsecure_RoundTrips() => WithEcDsa("P-256", (workspace, ec) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("legacy");
        using (workspace.UsePolicy(CryptoPolicy.AllowInsecure))
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
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.NistApproved);
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
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
}
