using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
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
    // RSA < 2048 is refused under Recommended (NIST SP 800-131A), so the 1024 case generates under an
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

    // === SHA-3 ===============================================================
    // The managed token hashes with the BCL, so these need the host's SHA-3; the case without it is pinned
    // below against the BCL's own RSA.

    public static TheoryData<string, string> Sha3HashesAndPaddings => new()
    {
        { "SHA3-256", "Pkcs1" }, { "SHA3-384", "Pkcs1" }, { "SHA3-512", "Pkcs1" },
        { "SHA3-256", "Pss" }, { "SHA3-384", "Pss" }, { "SHA3-512", "Pss" },
    };

    // SignData hashes on the token through CKM_SHA3_*_RSA_PKCS(_PSS), SignHash signs the caller's digest through
    // the raw mechanism, and the BCL verifies both.
    [Theory(SkipUnless = nameof(SHA3_256.IsSupported), SkipType = typeof(SHA3_256), Skip = "Requires " + nameof(SHA3_256.IsSupported))]
    [MemberData(nameof(Sha3HashesAndPaddings))]
    public void Sha3_SignDataAndSignHash_InteropWithBcl(string hashName, string paddingName) => WithRsa((_, rsa) =>
    {
        var hash = new HashAlgorithmName(hashName);
        var padding = paddingName == "Pss" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        byte[] data = Encoding.UTF8.GetBytes("sha-3 on a managed token");
        byte[] digest = CryptographicOperations.HashData(hash, data);
        using RSA bcl = BclPublic(rsa);

        byte[] overData = rsa.SignData(data, hash, padding);
        byte[] overDigest = rsa.SignHash(digest, hash, padding);

        Assert.True(bcl.VerifyData(data, overData, hash, padding));
        Assert.True(bcl.VerifyHash(digest, overDigest, hash, padding));
        Assert.True(rsa.VerifyHash(digest, overData, hash, padding));
        Assert.True(rsa.VerifyData(data, overDigest, hash, padding));
    });

    // The Stream overloads hash with the BCL's SHA-3, then sign or verify the digest.
    [Theory(SkipUnless = nameof(SHA3_256.IsSupported), SkipType = typeof(SHA3_256), Skip = "Requires " + nameof(SHA3_256.IsSupported))]
    [MemberData(nameof(Sha3HashesAndPaddings))]
    public void Sha3_Stream_RoundTrips(string hashName, string paddingName) => WithRsa((_, rsa) =>
    {
        var hash = new HashAlgorithmName(hashName);
        var padding = paddingName == "Pss" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        byte[] data = Encoding.UTF8.GetBytes("streamed sha-3");
        using var toSign = new MemoryStream(data);
        using var toVerify = new MemoryStream(data);

        byte[] sig = rsa.SignData(toSign, hash, padding);

        Assert.True(rsa.VerifyData(toVerify, sig, hash, padding));
        Assert.True(rsa.VerifyData(data, sig, hash, padding));
    });

    // Without the platform's SHA-3, the Stream overloads, which hash in managed code, fail as the BCL's RSA does.
    [Fact]
    public void Sha3_Stream_WithoutPlatformSha3_FailsAsTheBcl() => WithRsa((_, rsa) =>
    {
        Assert.SkipWhen(SHA3_256.IsSupported, "The host has SHA3-256.");
        using var bcl = RSA.Create(2048);

        foreach (var padding in (RSASignaturePadding[])[RSASignaturePadding.Pkcs1, RSASignaturePadding.Pss])
        {
            using var bclSignData = new MemoryStream([1, 2, 3]);
            using var rsaSignData = new MemoryStream([1, 2, 3]);
            using var bclVerifyData = new MemoryStream([1, 2, 3]);
            using var rsaVerifyData = new MemoryStream([1, 2, 3]);
            AssertSameFailureAsBcl(
                () => bcl.SignData(bclSignData, HashAlgorithmName.SHA3_256, padding),
                () => rsa.SignData(rsaSignData, HashAlgorithmName.SHA3_256, padding));
            AssertSameFailureAsBcl(
                () => bcl.VerifyData(bclVerifyData, new byte[256], HashAlgorithmName.SHA3_256, padding),
                () => rsa.VerifyData(rsaVerifyData, new byte[256], HashAlgorithmName.SHA3_256, padding));
        }
    });

    private static void AssertSameFailureAsBcl(Action bcl, Action adapter)
    {
        Exception expected = Assert.ThrowsAny<Exception>(bcl);
        Exception actual = Assert.ThrowsAny<Exception>(adapter);
        Assert.Equal(expected.GetType(), actual.GetType());
    }

    // A SHA-3 digest of the wrong length cannot be signed, and does not verify; no SHA-3 is computed for it.
    [Theory]
    [InlineData("SHA3-256", 32)]
    [InlineData("SHA3-384", 48)]
    [InlineData("SHA3-512", 64)]
    public void Sha3_SignHash_DigestOfTheWrongLength_Throws_AndDoesNotVerify(string hashName, int length) => WithRsa((_, rsa) =>
    {
        var hash = new HashAlgorithmName(hashName);

        Assert.Throws<CryptographicException>(() => rsa.SignHash(new byte[length - 1], hash, RSASignaturePadding.Pss));
        Assert.Throws<CryptographicException>(() => rsa.SignHash(new byte[length + 1], hash, RSASignaturePadding.Pkcs1));
        Assert.False(rsa.VerifyHash(new byte[length - 1], new byte[256], hash, RSASignaturePadding.Pss));
        Assert.False(rsa.VerifyHash(new byte[length + 1], new byte[256], hash, RSASignaturePadding.Pkcs1));
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

    public static TheoryData<string> Sha3Hashes => ["SHA3-256", "SHA3-384", "SHA3-512"];

    // OAEP with a SHA-3 hash and MGF1: token round-trip, and the token decrypts the BCL's ciphertext.
    [Theory(SkipUnless = nameof(SHA3_256.IsSupported), SkipType = typeof(SHA3_256), Skip = "Requires " + nameof(SHA3_256.IsSupported))]
    [MemberData(nameof(Sha3Hashes))]
    public void OaepSha3_EncryptDecrypt_RoundTrips_AndInteropsWithBcl(string hashName) => WithTransportRsa((_, rsa) =>
    {
        var oaep = RSAEncryptionPadding.CreateOaep(new HashAlgorithmName(hashName));
        byte[] plaintext = RandomNumberGenerator.GetBytes(32);
        using var bcl = RSA.Create(rsa.ExportParameters(includePrivateParameters: false));

        Assert.Equal(plaintext, rsa.Decrypt(rsa.Encrypt(plaintext, oaep), oaep));
        Assert.Equal(plaintext, rsa.Decrypt(bcl.Encrypt(plaintext, oaep), oaep));
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
    // CKR_ENCRYPTED_DATA_INVALID. The flipped byte is not the first: that one could take the value past the
    // modulus, which the adapter refuses before the token sees it.
    [Fact]
    public void Decrypt_TamperedOaepCiphertext_Throws() => WithTransportRsa((_, rsa) =>
    {
        byte[] plaintext = RandomNumberGenerator.GetBytes(32);
        byte[] ct = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        ct[ct.Length / 2] ^= 0xFF;

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA256));
        Assert.Equal(CKR.CKR_ENCRYPTED_DATA_INVALID, ex.ReturnValue);
    });

    [Theory]
    [InlineData("Pkcs1")]
    [InlineData("Oaep")]
    public void Decrypt_CiphertextNotBelowTheModulus_Throws(string padding) => WithTransportRsa((session, rsa) =>
        RSAPkcs11TestCases.AssertRefusesCiphertextNotBelowTheModulus(session, rsa, padding));

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

    // === A ciphertext the key cannot have produced never reaches the token ==
    // The fake's C_Decrypt answers CKR_OK with an empty plaintext whatever it is given, as some tokens answer
    // an empty ciphertext, so only the adapter can refuse one. Its key's modulus is 2048 bits.

    private static readonly byte[] FakeModulus = [0xC3, .. Enumerable.Repeat((byte)0x5A, 254), 0x6B];

    // A ciphertext of the modulus's length and below it, as the key could have produced.
    private static readonly byte[] FakeCiphertext = [0x01, .. new byte[255]];

    // CKA_MODULUS_BITS as the token's CK_ULONG, for the key's size, which the span entry points need.
    private static readonly byte[] FakeModulusBits =
        MemoryMarshal.AsBytes<NativeCULong>([(NativeCULong)(ulong)(FakeModulus.Length * 8)]).ToArray();

    private static (CKR, byte[]?) FakeRsaAttribute(CKA type) => type switch
    {
        CKA.CKA_MODULUS => (CKR.CKR_OK, FakeModulus),
        CKA.CKA_MODULUS_BITS => (CKR.CKR_OK, FakeModulusBits),
        _ => (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null),
    };

    // A private-only key, unless respondFor answers for each half. modulus answers for CKA_MODULUS, and
    // modulusBits for CKA_MODULUS_BITS, in place of the fake's.
    private static FakeKey LenientRsaKey(
        Action onDecrypt,
        ICryptoPolicy? policy = null,
        Func<CKA, (CKR, byte[]?)>? modulus = null,
        Func<CKA, (CKR, byte[]?)>? modulusBits = null,
        Func<ulong, CKA, (CKR, byte[]?)>? respondFor = null) =>
        FakeKeys.Create(
            CKK.CKK_RSA,
            ca => ca switch
            {
                CKA.CKA_MODULUS when modulus is not null => modulus(ca),
                CKA.CKA_MODULUS_BITS when modulusBits is not null => modulusBits(ca),
                _ => FakeRsaAttribute(ca),
            },
            policy ?? CryptoPolicy.AllowInsecure,
            decrypt: _ =>
            {
                onDecrypt();
                return [];
            },
            respondFor: respondFor);

    public static TheoryData<string, string> EncryptionPaddingsAndDecryptCalls()
    {
        var data = new TheoryData<string, string>();
        foreach (string padding in (string[])["Pkcs1", "OaepSHA256"])
        {
            foreach (string call in RSAPkcs11TestCases.DecryptCalls.Keys)
                data.Add(padding, call);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(EncryptionPaddingsAndDecryptCalls))]
    public void Decrypt_CiphertextNotFromTheKey_ThrowsWithoutTheToken(string paddingName, string call)
    {
        int decrypts = 0;
        using var key = LenientRsaKey(() => decrypts++);
        using var rsa = new RSAPkcs11(key);
        RSAEncryptionPadding padding = RSAPkcs11TestCases.EncryptionPadding(paddingName);
        var decrypt = RSAPkcs11TestCases.DecryptCalls[call];

        Assert.All(RSAPkcs11TestCases.CiphertextsNotFromTheKey(FakeModulus, FakeCiphertext), c =>
            Assert.Throws<CryptographicException>(() => decrypt(rsa, c.Ciphertext, padding)));
        Assert.Equal(0, decrypts);

        // Just below the modulus is a ciphertext the key could have produced.
        byte[] belowModulus = [.. FakeModulus];
        belowModulus[^1]--;
        Assert.Empty(decrypt(rsa, belowModulus, padding));
        Assert.Empty(decrypt(rsa, FakeCiphertext, padding));
        Assert.Equal(2, decrypts);
    }

    // The BCL's own RSA refuses the same ciphertexts with a CryptographicException.
    [Theory]
    [InlineData("Pkcs1")]
    [InlineData("OaepSHA256")]
    public void Decrypt_CiphertextNotFromTheKey_ThrowsAsTheBclDoes(string paddingName)
    {
        using var bcl = RSA.Create(2048);
        RSAEncryptionPadding padding = RSAPkcs11TestCases.EncryptionPadding(paddingName);
        byte[] ciphertext = bcl.Encrypt([0x2A], padding);
        var notFromTheKey = RSAPkcs11TestCases.CiphertextsNotFromTheKey(bcl.ExportParameters(false).Modulus!, ciphertext);

        Assert.All(notFromTheKey, c => Assert.All(RSAPkcs11TestCases.DecryptCalls.Values, decrypt =>
            Assert.ThrowsAny<CryptographicException>(() => decrypt(bcl, c.Ciphertext, padding))));
    }

    // The policy judges the padding, which the BCL validates before the ciphertext: a refused PKCS#1 v1.5 is
    // refused as such, whatever the ciphertext, and the token is not read for it.
    [Fact]
    public void Decrypt_Pkcs1_GatedByDefault_ThrowsBeforeTheCiphertextIsChecked()
    {
        int decrypts = 0, reads = 0;
        using var key = LenientRsaKey(() => decrypts++, CryptoPolicy.Recommended, ca =>
        {
            reads++;
            return (CKR.CKR_DEVICE_ERROR, null);
        });
        using var rsa = new RSAPkcs11(key);
        reads = 0; // The constructor reads the key's size.

        Assert.All(RSAPkcs11TestCases.CiphertextsNotFromTheKey(FakeModulus, FakeCiphertext), c =>
            Assert.Throws<CryptoPolicyViolationException>(() => rsa.Decrypt(c.Ciphertext, RSAEncryptionPadding.Pkcs1)));
        Assert.Throws<CryptoPolicyViolationException>(() => rsa.Decrypt(FakeCiphertext, RSAEncryptionPadding.Pkcs1));
        Assert.Equal(0, reads);
        Assert.Equal(0, decrypts);
    }

    // The modulus is read once, and a refused ciphertext does not read it again. For a key with no public half,
    // the constructor's read of the key's size already brought it.
    [Fact]
    public void Decrypt_Modulus_IsReadOnce()
    {
        int reads = 0;
        using var key = LenientRsaKey(() => { }, modulus: _ =>
        {
            reads++;
            return (CKR.CKR_OK, FakeModulus);
        });
        using var rsa = new RSAPkcs11(key);
        Assert.NotEqual(0, reads);
        reads = 0;

        rsa.Decrypt(FakeCiphertext, RSAEncryptionPadding.OaepSHA256);
        Assert.Throws<CryptographicException>(() => rsa.Decrypt(FakeModulus, RSAEncryptionPadding.OaepSHA256));
        Assert.Throws<CryptographicException>(() => rsa.Decrypt((byte[])[], RSAEncryptionPadding.OaepSHA256));
        rsa.Decrypt(FakeCiphertext, RSAEncryptionPadding.OaepSHA256);
        Assert.Equal(0, reads);
    }

    // The modulus is the private half's, the one that decrypts, even when a public half has another.
    [Fact]
    public void Decrypt_Modulus_IsThePrivateHalfs()
    {
        byte[] publicModulus = [0x80, .. new byte[255]];
        byte[] betweenThem = [0xA0, .. new byte[255]]; // not below the public half's, below the private half's
        int decrypts = 0;
        using var key = LenientRsaKey(() => decrypts++, respondFor: (handle, ca) =>
            ca == CKA.CKA_MODULUS && handle == 2 ? (CKR.CKR_OK, publicModulus) : FakeRsaAttribute(ca));
        using var rsa = new RSAPkcs11(key);

        Assert.Empty(rsa.Decrypt(betweenThem, RSAEncryptionPadding.OaepSHA256));
        Assert.Throws<CryptographicException>(() => rsa.Decrypt(FakeModulus, RSAEncryptionPadding.OaepSHA256));
        Assert.Equal(1, decrypts);
    }

    // The session's policy is asked once per decryption, whether the ciphertext is refused or decrypted.
    [Fact]
    public void Decrypt_AsksThePolicyOnce()
    {
        var policy = new CountingPolicy();
        using var key = LenientRsaKey(() => { }, policy);
        using var rsa = new RSAPkcs11(key);

        rsa.Decrypt(FakeCiphertext, RSAEncryptionPadding.OaepSHA256);
        Assert.Equal(1, policy.Decrypts);
        Assert.Throws<CryptographicException>(() => rsa.Decrypt(FakeModulus, RSAEncryptionPadding.OaepSHA256));
        Assert.Equal(2, policy.Decrypts);
    }

    private sealed class CountingPolicy : ICryptoPolicy
    {
        public int Decrypts { get; private set; }
        public string Name => "Counting";
        public bool AllowsOverride => false;
        public PolicyDecision Evaluate(PolicyRequest request)
        {
            if (request is MechanismUseRequest { Operation: CryptoOperation.Decrypt })
                Decrypts++;
            return PolicyDecision.Allow;
        }
    }

    // Once the modulus is read, a disposed key still throws rather than the cached modulus refusing the
    // ciphertext, and before the policy is asked: a PKCS#1 v1.5 the policy would refuse is no exception.
    [Fact]
    public void Decrypt_CiphertextNotFromTheKey_DisposedKey_ThrowsObjectDisposed()
    {
        using var key = LenientRsaKey(() => { }, CryptoPolicy.Recommended);
        using var rsa = new RSAPkcs11(key);
        rsa.Decrypt(FakeCiphertext, RSAEncryptionPadding.OaepSHA256);
        key.Key.Dispose();

        Assert.Throws<ObjectDisposedException>(() => rsa.Decrypt(FakeModulus, RSAEncryptionPadding.OaepSHA256));
        Assert.Throws<ObjectDisposedException>(() => rsa.Decrypt((byte[])[], RSAEncryptionPadding.OaepSHA256));
        Assert.Throws<ObjectDisposedException>(() => rsa.Decrypt(FakeCiphertext, RSAEncryptionPadding.Pkcs1));
    }

    // A modulus whose read fails throws as the read does; one of zero would refuse every ciphertext, so it
    // is an invalid attribute instead. Neither reaches the token.
    [Theory]
    [InlineData(CKR.CKR_DEVICE_ERROR, CKR.CKR_DEVICE_ERROR)]
    [InlineData(CKR.CKR_OK, CKR.CKR_ATTRIBUTE_VALUE_INVALID)]
    public void Decrypt_UnusableModulus_Throws(CKR read, CKR expected)
    {
        int decrypts = 0;
        using var key = LenientRsaKey(() => decrypts++, modulus: _ => (read, read == CKR.CKR_OK ? [0x00, 0x00] : null));
        using var rsa = new RSAPkcs11(key);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => rsa.Decrypt(FakeCiphertext, RSAEncryptionPadding.OaepSHA256));
        Assert.Equal(expected, ex.ReturnValue);
        Assert.Equal(0, decrypts);
    }

    // A private key need not expose its modulus. Its size still fixes the ciphertext's length, and a
    // ciphertext of that length goes to the token, as before the check.
    [Theory]
    [InlineData(CKR.CKR_ATTRIBUTE_SENSITIVE)]
    [InlineData(CKR.CKR_ATTRIBUTE_TYPE_INVALID)]
    public void Decrypt_UnreadableModulus_ChecksTheLengthOnly(CKR read)
    {
        int decrypts = 0;
        using var key = LenientRsaKey(() => decrypts++, modulus: _ => (read, null));
        using var rsa = new RSAPkcs11(key);

        var notFromTheKey = RSAPkcs11TestCases.CiphertextsNotFromTheKey(FakeModulus, FakeCiphertext);
        foreach ((string name, byte[] ciphertext) in notFromTheKey)
        {
            if (ciphertext.Length == FakeModulus.Length)
                Assert.Empty(rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256));
            else
                Assert.Throws<CryptographicException>(() => rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256));
        }
        Assert.Equal(notFromTheKey.Count(c => c.Ciphertext.Length == FakeModulus.Length), decrypts);
    }

    // With neither the modulus nor its size, every ciphertext goes to the token, as before the check.
    [Fact]
    public void Decrypt_NoModulusNorSize_LeavesTheCiphertextToTheToken()
    {
        int decrypts = 0;
        using var key = LenientRsaKey(
            () => decrypts++,
            modulus: _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null),
            modulusBits: _ => (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null));
        using var rsa = new RSAPkcs11(key);

        var notFromTheKey = RSAPkcs11TestCases.CiphertextsNotFromTheKey(FakeModulus, FakeCiphertext);
        Assert.All(notFromTheKey, c => Assert.Empty(rsa.Decrypt(c.Ciphertext, RSAEncryptionPadding.OaepSHA256)));
        Assert.Equal(notFromTheKey.Length, decrypts);
    }

    // Pkcs11Key's own Decrypt and Unwrap refuse them too, under either RSA encryption mechanism. The fake has no
    // C_UnwrapKey, so an unwrap that reaches the token throws CKR_FUNCTION_NOT_SUPPORTED.
    [Theory]
    [InlineData(CKM.CKM_RSA_PKCS)]
    [InlineData(CKM.CKM_RSA_PKCS_OAEP)]
    public void Key_DecryptAndUnwrap_CiphertextNotFromTheKey_ThrowsWithoutTheToken(CKM type)
    {
        int decrypts = 0;
        using var key = LenientRsaKey(() => decrypts++);
        var mechanism = type == CKM.CKM_RSA_PKCS ? new Mechanism(CKM.CKM_RSA_PKCS) : Pkcs11MechanismMap.RsaOaep(HashAlgorithmName.SHA256);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Build();

        Assert.All(RSAPkcs11TestCases.CiphertextsNotFromTheKey(FakeModulus, FakeCiphertext), c =>
        {
            Assert.Throws<CryptographicException>(() => key.Key.Decrypt(mechanism, c.Ciphertext));
            Assert.Throws<CryptographicException>(() => key.Key.Unwrap(mechanism, c.Ciphertext, template));
        });
        Assert.Equal(0, decrypts);

        Assert.Empty(key.Key.Decrypt(mechanism, FakeCiphertext));
        Assert.Equal(1, decrypts);
        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Key.Unwrap(mechanism, FakeCiphertext, template));
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    // Raw RSA (CKM_RSA_X_509) is not checked: PKCS#11 lets its input be shorter than the modulus.
    [Fact]
    public void Key_Decrypt_RawRsa_LeavesTheCiphertextToTheToken()
    {
        int decrypts = 0;
        using var key = LenientRsaKey(() => decrypts++);
        Assert.Empty(key.Key.Decrypt(new Mechanism(CKM.CKM_RSA_X_509), FakeCiphertext[..^1]));
        Assert.Equal(1, decrypts);
    }

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
