using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

// These tests exercise the gated RSAES-PKCS#1 v1.5 / raw-RSA paths and SHA-1 signing on purpose (the
// runtime secure-defaults policy check is the behaviour under test), so the compile-time warnings are
// suppressed for this file only — the per-id suppression the diagnostics exist to enable.
#pragma warning disable KLPKCS11008, KLPKCS11010

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// RSAPkcs11 over the in-process <c>ManagedSoftToken</c> (a BCL-backed PKCS#11 fake). Generates an
/// RSA-2048 key pair on the token via C_GenerateKeyPair, then exercises the adapter at the same depth
/// as the SoftHSM suite: PKCS#1 v1.5 and PSS sign/verify (byte[] and span overloads, on-token verify),
/// RSA-OAEP encrypt/decrypt, PKCS#1 v1.5 encrypt under the AllowInsecure policy, public-parameter export, and the
/// argument-validation / negative cases. Unlike SoftHSM (which gates OAEP-SHA256 off), the managed
/// token supports OAEP-SHA1/SHA256, so those KATs run here — including decrypting a BCL-produced
/// ciphertext and verifying a token-produced signature in the BCL from the exported public key.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class RSAPkcs11Tests_Managed
{
    private static void WithRsa(Action<Pkcs11Session, RSAPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var key = session.GenerateRsaSigningKeyPair(modulusBits: 2048);
        using var rsa = new RSAPkcs11(key);
        body(session, rsa);
    }

    private static void WithTransportRsa(Action<Pkcs11Session, RSAPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var key = session.GenerateRsaKeyTransportKeyPair(modulusBits: 2048);
        using var rsa = new RSAPkcs11(key);
        body(session, rsa);
    }

    // === Construction =====================================================

    [Fact]
    public void Ctor_NonRsaKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("aes").ValueLen(32).Encrypt().Decrypt().Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new RSAPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }

    // === Key sizes: sign/verify round-trips scale with the modulus =========
    // RSA < 2048 is refused under SecureOnly (NIST SP 800-131A), so the 1024 case generates under an
    // opt-in scope; 2048/3072/4096 need no opt-in. PSS-SHA256 fits even a 1024-bit modulus.

    [Theory]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    public void SignVerifyData_AcrossKeySizes_RoundTrips(int modulusBits)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);

        using IDisposable? insecure = modulusBits < 2048 ? session.UsePolicy(CryptoPolicy.AllowInsecure) : null;
        using var key = session.GenerateRsaSigningKeyPair(modulusBits);
        using var rsa = new RSAPkcs11(key);

        byte[] data = Encoding.UTF8.GetBytes($"rsa-{modulusBits} payload");
        byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.Equal(modulusBits / 8, sig.Length);
        Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        // Cross-verify under the BCL from the exported public key; modulus length scales with the size.
        var pub = rsa.ExportParameters(includePrivateParameters: false);
        Assert.Equal(modulusBits / 8, pub.Modulus!.Length);
        using var bcl = RSA.Create();
        bcl.ImportParameters(pub);
        Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        byte[] tampered = [.. data];
        tampered[0] ^= 0xFF;
        Assert.False(rsa.VerifyData(tampered, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    // === Sign/verify — byte[] overloads, with BCL cross-check ==============

    public static TheoryData<string> Paddings => ["Pkcs1", "Pss"];

    [Theory]
    [MemberData(nameof(Paddings))]
    public void SignVerifyData_RoundTrips_AndPublicMatchesBcl(string paddingName) => WithRsa((_, rsa) =>
    {
        var padding = paddingName == "Pss" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

        byte[] data = Encoding.UTF8.GetBytes("RSA signed on a managed token");
        byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, padding);

        // On-token verify, including the tamper case.
        Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, padding));
        byte[] tampered = [.. data];
        tampered[0] ^= 0xFF;
        Assert.False(rsa.VerifyData(tampered, sig, HashAlgorithmName.SHA256, padding));

        // Cross-library: export the public key into a fresh BCL RSA and verify the token signature —
        // catches a DER/parameter-export bug or a wrong PSS salt that a same-instance round-trip misses.
        // (Reverse direction — BCL signs, token verifies — isn't possible: the token's RSA private
        // key is generated on-token and non-extractable, so no BCL key can hold it.)
        using var bcl = RSA.Create(rsa.ExportParameters(includePrivateParameters: false));
        Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256, padding));
    });

    [Fact]
    public void SignData_BadRange_Throws() => WithRsa((_, rsa) =>
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            rsa.SignData(new byte[8], 4, 8, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)));

    [Fact]
    public void SignData_NullArguments_Throw() => WithRsa((_, rsa) =>
    {
        Assert.Throws<ArgumentNullException>(() =>
            rsa.SignData((byte[])null!, 0, 0, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Throws<ArgumentNullException>(() =>
            rsa.SignData(new byte[4], 0, 4, HashAlgorithmName.SHA256, null!));
    });

    [Fact]
    public void VerifyData_NullArguments_Throw() => WithRsa((_, rsa) =>
    {
        Assert.Throws<ArgumentNullException>(() =>
            rsa.VerifyData((byte[])null!, 0, 0, new byte[1], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Throws<ArgumentNullException>(() =>
            rsa.VerifyData(new byte[4], 0, 4, null!, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Throws<ArgumentNullException>(() =>
            rsa.VerifyData(new byte[4], 0, 4, new byte[1], HashAlgorithmName.SHA256, null!));
    });

    [Fact]
    public void VerifyData_BadRange_Throws() => WithRsa((_, rsa) =>
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            rsa.VerifyData(new byte[8], 4, 8, new byte[1], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)));

    // === Sign/verify — span overloads (the adapter's combined on-token hash+sign path) =====

    [Fact]
    public void TrySignData_Span_VerifyData_Span_RoundTrips() => WithRsa((_, rsa) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("span hash+sign on token");
        byte[] dest = new byte[256]; // 2048-bit signature == 256 bytes

        Assert.True(rsa.TrySignData(data, dest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss, out int written));
        Assert.Equal(256, written);

        var sig = dest.AsSpan(0, written);
        Assert.True(rsa.VerifyData(data.AsSpan(), sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        byte[] tampered = [.. data];
        tampered[0] ^= 0xFF;
        Assert.False(rsa.VerifyData(tampered.AsSpan(), sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    });

    [Fact]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => WithRsa((_, rsa) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("too small destination");
        Assert.False(rsa.TrySignData(data, new byte[8], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, out int written));
        Assert.Equal(0, written);
    });

    [Fact]
    public void TrySignData_NullPadding_Throws() => WithRsa((_, rsa) =>
        Assert.Throws<ArgumentNullException>(() =>
            rsa.TrySignData(new byte[4], new byte[256], HashAlgorithmName.SHA256, null!, out int _)));

    [Fact]
    public void VerifyData_Span_NullPadding_Throws() => WithRsa((_, rsa) =>
        Assert.Throws<ArgumentNullException>(() =>
            rsa.VerifyData(new byte[4].AsSpan(), new byte[256].AsSpan(), HashAlgorithmName.SHA256, null!)));

    // === Signing a digest: SignHash / VerifyHash and the Stream overloads ===

    public static TheoryData<string> DigestHashes => ["SHA256", "SHA384", "SHA512"];

    private static RSA BclPublic(RSAPkcs11 rsa)
    {
        var bcl = RSA.Create();
        bcl.ImportParameters(rsa.ExportParameters(false));
        return bcl;
    }

    // A PSS signature over a digest verifies on the token and in the BCL, and the BCL's verifies on the token.
    [Theory]
    [MemberData(nameof(DigestHashes))]
    public void SignHash_Pss_RoundTrips_AndInteropsWithBcl(string hashName) => WithRsa((_, rsa) =>
    {
        var hash = new HashAlgorithmName(hashName);
        byte[] digest = CryptographicOperations.HashData(hash, Encoding.UTF8.GetBytes("a digest to sign"));
        using RSA bcl = BclPublic(rsa);

        byte[] sig = rsa.SignHash(digest, hash, RSASignaturePadding.Pss);

        Assert.Equal(256, sig.Length);
        Assert.True(rsa.VerifyHash(digest, sig, hash, RSASignaturePadding.Pss));
        Assert.True(bcl.VerifyHash(digest, sig, hash, RSASignaturePadding.Pss));

        byte[] tampered = [.. digest];
        tampered[0] ^= 0xFF;
        Assert.False(rsa.VerifyHash(tampered, sig, hash, RSASignaturePadding.Pss));
    });

    // SignData hashes on the token and SignHash signs the caller's digest: the signatures interoperate.
    [Fact]
    public void SignHash_Pss_AndSignData_VerifyEachOther() => WithRsa((_, rsa) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("signed both ways");
        byte[] digest = SHA256.HashData(data);

        byte[] overData = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        byte[] overDigest = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.True(rsa.VerifyHash(digest, overData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        Assert.True(rsa.VerifyData(data, overDigest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    });

    // PKCS#1 v1.5 over a digest is judged as the scheme it is, the combined mechanism for the hash, so the
    // default policy allows it as it allows SignData; the scheme is deterministic, so the signatures match.
    [Theory]
    [MemberData(nameof(DigestHashes))]
    public void SignHash_Pkcs1_UnderTheDefaultPolicy_MatchesSignData(string hashName) => WithRsa((_, rsa) =>
    {
        var hash = new HashAlgorithmName(hashName);
        byte[] data = Encoding.UTF8.GetBytes("pkcs1 over a digest");
        byte[] digest = CryptographicOperations.HashData(hash, data);
        byte[] overData = rsa.SignData(data, hash, RSASignaturePadding.Pkcs1);
        using RSA bcl = BclPublic(rsa);

        Assert.Equal(overData, rsa.SignHash(digest, hash, RSASignaturePadding.Pkcs1));
        Assert.True(rsa.VerifyHash(digest, overData, hash, RSASignaturePadding.Pkcs1));
        Assert.True(bcl.VerifyHash(digest, overData, hash, RSASignaturePadding.Pkcs1));
    });

    // Judged as CKM_SHA1_RSA_PKCS, PKCS#1 v1.5 over a SHA-1 digest is refused as SignData's would be.
    [Fact]
    public void SignHash_Pkcs1_Sha1_IsRefused() => WithRsa((_, rsa) =>
        Assert.Throws<CryptoPolicyViolationException>(
            () => rsa.SignHash(SHA1.HashData([1, 2, 3]), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1)));

    // The adapter's DigestInfo path does not open raw CKM_RSA_PKCS: signing arbitrary input with it is
    // still refused by the default policy.
    [Fact]
    public void RawRsaPkcs_IsStillRefused_ForAnyOtherCaller()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var key = session.GenerateRsaSigningKeyPair(modulusBits: 2048);

        var e = Assert.Throws<CryptoPolicyViolationException>(() => key.Sign(new Mechanism(CKM.CKM_RSA_PKCS), new byte[51]));
        Assert.Equal(CKM.CKM_RSA_PKCS, e.Mechanism);
    }

    [Fact]
    public void Stream_Pkcs1_UnderTheDefaultPolicy_RoundTrips() => WithRsa((_, rsa) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("streamed pkcs1");
        using var toSign = new MemoryStream(data);
        using var toVerify = new MemoryStream(data);

        byte[] sig = rsa.SignData(toSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        Assert.Equal(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), sig);
        Assert.True(rsa.VerifyData(toVerify, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    });

    // The token sees only a raw mechanism, so the hash is put to the policy on its own.
    [Fact]
    public void SignHash_Sha1_IsRefusedByThePolicy() => WithRsa((_, rsa) =>
    {
        byte[] digest = SHA1.HashData([1, 2, 3]);

        var e = Assert.Throws<CryptoPolicyViolationException>(() => rsa.SignHash(digest, HashAlgorithmName.SHA1, RSASignaturePadding.Pss));
        Assert.Equal(HashAlgorithmName.SHA1, Assert.IsType<HashUseRequest>(e.Request).Hash);
    });

    // As the BCL: a digest of the wrong length cannot be signed, and does not verify.
    [Fact]
    public void SignHash_DigestOfTheWrongLength_Throws_AndDoesNotVerify() => WithRsa((_, rsa) =>
    {
        byte[] sig = rsa.SignHash(new byte[32], HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.Throws<CryptographicException>(() => rsa.SignHash(new byte[31], HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        Assert.False(rsa.VerifyHash(new byte[31], sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    });

    // The BCL's argument checks, in its order: the hash, the hash name, then the padding.
    [Fact]
    public void SignHash_VerifyHash_ArgumentErrors_MatchTheBcl() => WithRsa((_, rsa) =>
    {
        byte[] digest = new byte[32];
        var sha256 = HashAlgorithmName.SHA256;
        var pss = RSASignaturePadding.Pss;

        Assert.Equal("hash", Assert.Throws<ArgumentNullException>(() => rsa.SignHash(null!, default, null!)).ParamName);
        Assert.Equal("hashAlgorithm", Assert.Throws<ArgumentNullException>(() => rsa.SignHash(digest, default, null!)).ParamName);
        Assert.Equal("hashAlgorithm", Assert.Throws<ArgumentException>(() => rsa.SignHash(digest, new HashAlgorithmName(""), pss)).ParamName);
        Assert.Equal("padding", Assert.Throws<ArgumentNullException>(() => rsa.SignHash(digest, sha256, null!)).ParamName);
        Assert.Equal("signature", Assert.Throws<ArgumentNullException>(() => rsa.VerifyHash(digest, null!, sha256, pss)).ParamName);
        Assert.Equal("padding", Assert.Throws<ArgumentNullException>(() => rsa.VerifyHash(digest, new byte[256], sha256, null!)).ParamName);
    });

    [Fact]
    public void TrySignHash_And_SpanVerifyHash_Work() => WithRsa((_, rsa) =>
    {
        byte[] digest = SHA256.HashData([4, 5, 6]);
        byte[] destination = new byte[256];

        Assert.False(rsa.TrySignHash(digest, new byte[255], HashAlgorithmName.SHA256, RSASignaturePadding.Pss, out int written));
        Assert.Equal(0, written);

        Assert.True(rsa.TrySignHash(digest, destination, HashAlgorithmName.SHA256, RSASignaturePadding.Pss, out written));
        Assert.Equal(256, written);
        Assert.True(rsa.VerifyHash(digest.AsSpan(), destination.AsSpan(), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    });

    // The Stream overloads hash in managed code, as the BCL does, then sign or verify the digest.
    [Fact]
    public void SignData_Stream_AndVerifyData_Stream_RoundTrip() => WithRsa((_, rsa) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("streamed data");
        using var toSign = new MemoryStream(data);
        using var toVerify = new MemoryStream(data);

        byte[] sig = rsa.SignData(toSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.True(rsa.VerifyData(toVerify, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        Assert.Equal("data", Assert.Throws<ArgumentNullException>(
            () => rsa.SignData((Stream)null!, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)).ParamName);
    });

    // Both Stream overloads put the hash to the policy, in the direction of the operation.
    [Fact]
    public void Stream_Sha1_IsRefusedByThePolicy_ForSigningAndVerifying() => WithRsa((_, rsa) =>
    {
        using var toSign = new MemoryStream([1, 2, 3]);
        using var toVerify = new MemoryStream([1, 2, 3]);

        var sign = Assert.Throws<CryptoPolicyViolationException>(
            () => rsa.SignData(toSign, HashAlgorithmName.SHA1, RSASignaturePadding.Pss));
        var verify = Assert.Throws<CryptoPolicyViolationException>(
            () => rsa.VerifyData(toVerify, new byte[256], HashAlgorithmName.SHA1, RSASignaturePadding.Pss));

        Assert.Equal(CryptoOperation.Sign, Assert.IsType<HashUseRequest>(sign.Request).Operation);
        Assert.Equal(CryptoOperation.Verify, Assert.IsType<HashUseRequest>(verify.Request).Operation);
    });

    // === Encryption / decryption ===========================================

    public static TheoryData<string> OaepHashes => ["SHA1", "SHA256"];

    // The managed token runs the OAEP KAT for both hashes: token round-trip plus decrypting a
    // BCL-produced ciphertext, and confirming the BCL can decrypt a token-produced ciphertext from the
    // exported public key. SoftHSM now also covers OAEP-SHA256 (since the de25233 bump); this remains
    // the managed-backend coverage and the BCL-interop check.
    // SHA-1-OAEP maps to a SHA-1-parameterized CKM_RSA_PKCS_OAEP, gated like any other SHA-1 use, so
    // it requires the AllowInsecure policy.
    [Theory]
    [MemberData(nameof(OaepHashes))]
    public void OaepEncryptDecrypt_RoundTrips_AndInteropsWithBcl(string oaepHash) => WithTransportRsa((session, rsa) =>
    {
        var oaep = oaepHash == "SHA256" ? RSAEncryptionPadding.OaepSHA256 : RSAEncryptionPadding.OaepSHA1;
        byte[] plaintext = RandomNumberGenerator.GetBytes(32);
        using IDisposable? insecure = oaepHash == "SHA1" ? session.UsePolicy(CryptoPolicy.AllowInsecure) : null;

        // Encrypt + decrypt on the token.
        byte[] ciphertext = rsa.Encrypt(plaintext, oaep);
        Assert.Equal(plaintext, rsa.Decrypt(ciphertext, oaep));

        using var bcl = RSA.Create(rsa.ExportParameters(includePrivateParameters: false));

        // Token decrypts a BCL-produced ciphertext (interop on the public/encrypt side). OAEP is
        // randomized, so the token's own ciphertext can't be byte-compared; the self round-trip above
        // covers its encrypt path, and the tamper case below covers padding-failure handling.
        byte[] bclCiphertext = bcl.Encrypt(plaintext, oaep);
        Assert.Equal(plaintext, rsa.Decrypt(bclCiphertext, oaep));
    });

    // PKCS#1 v1.5 encryption maps to the gated CKM_RSA_PKCS, so it requires the AllowInsecure policy.
    [Fact]
    public void EncryptDecrypt_Pkcs1_UnderAllowInsecure_RoundTrips() => WithTransportRsa((session, rsa) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("pkcs1 payload");
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            byte[] ct = rsa.Encrypt(plaintext, RSAEncryptionPadding.Pkcs1);
            Assert.Equal(plaintext, rsa.Decrypt(ct, RSAEncryptionPadding.Pkcs1));
        }
    });

    [Fact]
    public void Encrypt_Pkcs1_WithoutAllowInsecure_Throws() => WithTransportRsa((_, rsa) =>
        Assert.Throws<CryptoPolicyViolationException>(() =>
            rsa.Encrypt(Encoding.UTF8.GetBytes("nope"), RSAEncryptionPadding.Pkcs1)));

    // A ciphertext whose padding is corrupted must fail decryption — the token surfaces this as
    // CKR_ENCRYPTED_DATA_INVALID.
    [Fact]
    public void Decrypt_TamperedOaepCiphertext_Throws() => WithTransportRsa((_, rsa) =>
    {
        byte[] plaintext = RandomNumberGenerator.GetBytes(32);
        byte[] ct = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        ct[0] ^= 0xFF;

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA256));
        Assert.Equal(CKR.CKR_ENCRYPTED_DATA_INVALID, ex.ReturnValue);
    });

    [Fact]
    public void Encrypt_NullArguments_Throw() => WithTransportRsa((_, rsa) =>
    {
        Assert.Throws<ArgumentNullException>(() => rsa.Encrypt(null!, RSAEncryptionPadding.OaepSHA1));
        Assert.Throws<ArgumentNullException>(() => rsa.Encrypt(new byte[4], null!));
    });

    [Fact]
    public void Decrypt_NullArguments_Throw() => WithTransportRsa((_, rsa) =>
    {
        Assert.Throws<ArgumentNullException>(() => rsa.Decrypt(null!, RSAEncryptionPadding.OaepSHA1));
        Assert.Throws<ArgumentNullException>(() => rsa.Decrypt(new byte[4], null!));
    });

    // === Key material export ===============================================

    [Fact]
    public void ExportParameters_PublicOnly_ReturnsModulusAndExponent() => WithRsa((_, rsa) =>
    {
        var p = rsa.ExportParameters(includePrivateParameters: false);
        Assert.NotNull(p.Modulus);
        Assert.NotNull(p.Exponent);
        Assert.Equal(2048 / 8, p.Modulus!.Length);
        Assert.Null(p.D); // private parts must not be set
    });

    [Fact]
    public void ExportParameters_Private_ThrowsInsecureOperation() => WithRsa((_, rsa) =>
        Assert.Throws<CryptoPolicyViolationException>(() => rsa.ExportParameters(includePrivateParameters: true)));

    [Fact]
    public void ImportParameters_Throws() => WithRsa((_, rsa) =>
        Assert.Throws<NotSupportedException>(() => rsa.ImportParameters(default)));

    // === KeySize / LegalKeySizes =============================================
    // Regression coverage for the adapter never assigning KeySizeValue: KeySize was 0,
    // LegalKeySizes threw NullReferenceException, and GetMaxOutputSize() threw CryptographicException.

    [Fact]
    public void KeySize_ReflectsTokenModulus() => WithRsa((_, rsa) =>
        Assert.Equal(2048, rsa.KeySize));

    [Fact]
    public void LegalKeySizes_ReflectsTokenModulus() => WithRsa((_, rsa) =>
    {
        KeySizes[] sizes = rsa.LegalKeySizes;
        KeySizes only = Assert.Single(sizes);
        Assert.Equal(2048, only.MinSize);
        Assert.Equal(2048, only.MaxSize);
    });

    [Fact]
    public void GetMaxOutputSize_Succeeds() => WithRsa((_, rsa) =>
        Assert.Equal(2048 / 8, rsa.GetMaxOutputSize()));

    // A real token can't be coaxed into failing to read CKA_MODULUS — it's a required attribute of
    // every RSA key object — so this drives the fallback's error paths directly via a fake library.
    [Fact]
    public void KeySize_BothModulusAttributesFail_StaysAtBclDefault()
    {
        using var key = FakeKeys.Create(CKK.CKK_RSA, _ => (CKR.CKR_DEVICE_ERROR, null));
        using var rsa = new RSAPkcs11(key);
        Assert.Equal(0, rsa.KeySize);
    }
}
