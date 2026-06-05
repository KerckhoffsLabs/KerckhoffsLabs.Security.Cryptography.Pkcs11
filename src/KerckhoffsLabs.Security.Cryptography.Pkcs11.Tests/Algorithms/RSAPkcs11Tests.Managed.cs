using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// RSAPkcs11 over the in-process <c>ManagedSoftToken</c> (a BCL-backed PKCS#11 fake). Generates an
/// RSA-2048 key pair on the token via C_GenerateKeyPair, then exercises the adapter at the same depth
/// as the SoftHSM suite: PKCS#1 v1.5 and PSS sign/verify (byte[] and span overloads, on-token verify),
/// RSA-OAEP encrypt/decrypt, PKCS#1 v1.5 encrypt under AllowInsecure, public-parameter export, and the
/// argument-validation / negative cases. Unlike SoftHSM (which gates OAEP-SHA256 off), the managed
/// token supports OAEP-SHA1/SHA256, so those KATs run here — including decrypting a BCL-produced
/// ciphertext and verifying a token-produced signature in the BCL from the exported public key.
/// </summary>
public sealed class RSAPkcs11Tests_Managed
{
    private static void WithRsa(Action<Pkcs11Workspace, RSAPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var key = workspace.GenerateRsaKeyPair(modulusBits: 2048);
        using var rsa = new RSAPkcs11(key);
        body(workspace, rsa);
    }

    // === Construction =====================================================

    [Fact]
    public void Ctor_NonRsaKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("aes").ValueLen(32).Encrypt().Decrypt().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new RSAPkcs11(key));
        Assert.Equal("key", ex.ParamName);
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

    // === Encryption / decryption ===========================================

    public static TheoryData<string> OaepHashes => ["SHA1", "SHA256"];

    // RSA-OAEP is gated off on SoftHSM (SoftHsmSupportsOaepSha256 = false), so its KAT skips there —
    // the managed token runs it: token round-trip plus decrypting a BCL-produced ciphertext, and
    // confirming the BCL can decrypt a token-produced ciphertext from the exported public key.
    [Theory]
    [MemberData(nameof(OaepHashes))]
    public void OaepEncryptDecrypt_RoundTrips_AndInteropsWithBcl(string oaepHash) => WithRsa((_, rsa) =>
    {
        var oaep = oaepHash == "SHA256" ? RSAEncryptionPadding.OaepSHA256 : RSAEncryptionPadding.OaepSHA1;
        byte[] plaintext = RandomNumberGenerator.GetBytes(32);

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

    // PKCS#1 v1.5 encryption maps to the gated CKM_RSA_PKCS, so it requires AllowInsecure.
    [Fact]
    public void EncryptDecrypt_Pkcs1_UnderAllowInsecure_RoundTrips() => WithRsa((workspace, rsa) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("pkcs1 payload");
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = rsa.Encrypt(plaintext, RSAEncryptionPadding.Pkcs1);
            Assert.Equal(plaintext, rsa.Decrypt(ct, RSAEncryptionPadding.Pkcs1));
        }
    });

    [Fact]
    public void Encrypt_Pkcs1_WithoutAllowInsecure_Throws() => WithRsa((_, rsa) =>
        Assert.Throws<InsecureOperationException>(() =>
            rsa.Encrypt(Encoding.UTF8.GetBytes("nope"), RSAEncryptionPadding.Pkcs1)));

    // A ciphertext whose padding is corrupted must fail decryption — the token surfaces this as
    // CKR_ENCRYPTED_DATA_INVALID.
    [Fact]
    public void Decrypt_TamperedOaepCiphertext_Throws() => WithRsa((_, rsa) =>
    {
        byte[] plaintext = RandomNumberGenerator.GetBytes(32);
        byte[] ct = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        ct[0] ^= 0xFF;

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA256));
        Assert.Equal(CKR.CKR_ENCRYPTED_DATA_INVALID, ex.ReturnValue);
    });

    [Fact]
    public void Encrypt_NullArguments_Throw() => WithRsa((_, rsa) =>
    {
        Assert.Throws<ArgumentNullException>(() => rsa.Encrypt(null!, RSAEncryptionPadding.OaepSHA1));
        Assert.Throws<ArgumentNullException>(() => rsa.Encrypt(new byte[4], null!));
    });

    [Fact]
    public void Decrypt_NullArguments_Throw() => WithRsa((_, rsa) =>
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
        Assert.Throws<InsecureOperationException>(() => rsa.ExportParameters(includePrivateParameters: true)));

    [Fact]
    public void ImportParameters_Throws() => WithRsa((_, rsa) =>
        Assert.Throws<NotSupportedException>(() => rsa.ImportParameters(default)));
}
