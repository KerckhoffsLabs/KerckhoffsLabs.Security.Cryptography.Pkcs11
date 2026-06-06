using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

[Collection("SoftHsm")]
public sealed class RSAPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;
    public static bool SoftHsmSupportsOaepSha256 => SoftHsmBackendFixture.SoftHsmSupportsOaepSha256;

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static Pkcs11Key GenerateRsaKey(Pkcs11Workspace workspace)
    {
        string label = $"rsa-prov-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().Encrypt().ModulusBits(2048)
            .PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Decrypt().Build();

        return workspace.GenerateKey(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), privTpl, pubTpl);
    }

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    // Generates a 2048-bit RSA key pair, wraps it as RSAPkcs11, runs the body with the workspace
    // (some tests need AllowInsecureScope) and the adapter, then destroys both objects.
    private void WithRsa(Action<Pkcs11Workspace, RSAPkcs11> body)
    {
        using var workspace = OpenWorkspace();
        var key = GenerateRsaKey(workspace);
        try
        {
            using var rsa = new RSAPkcs11(key);
            body(workspace, rsa);
        }
        finally
        {
            try { key.Delete(); }
            catch { /* best-effort cleanup */ }
            key.Dispose();
        }
    }

    // === Construction =====================================================

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonRsaKey_Throws()
    {
        using var workspace = OpenWorkspace();
        string label = $"rsa-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new RSAPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Sign/verify — byte[] overloads ====================================

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignVerifyData_Pkcs1_RoundTrips() => WithRsa((_, rsa) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("test");
        byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        data[0] ^= 0xFF;
        Assert.False(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignVerifyData_Pss_RoundTrips() => WithRsa((_, rsa) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("test");
        byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        byte[] tamperedSig = [.. sig];
        tamperedSig[0] ^= 0xFF;
        Assert.False(rsa.VerifyData(data, tamperedSig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignData_NullArguments_Throw() => WithRsa((_, rsa) =>
    {
        Assert.Throws<ArgumentNullException>(() =>
            rsa.SignData((byte[])null!, 0, 0, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Throws<ArgumentNullException>(() =>
            rsa.SignData(new byte[4], 0, 4, HashAlgorithmName.SHA256, null!));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignData_BadRange_Throws() => WithRsa((_, rsa) =>
    {
        byte[] data = new byte[8];
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            rsa.SignData(data, 4, 8, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void VerifyData_NullArguments_Throw() => WithRsa((_, rsa) =>
    {
        Assert.Throws<ArgumentNullException>(() =>
            rsa.VerifyData((byte[])null!, 0, 0, new byte[1], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Throws<ArgumentNullException>(() =>
            rsa.VerifyData(new byte[4], 0, 4, null!, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Throws<ArgumentNullException>(() =>
            rsa.VerifyData(new byte[4], 0, 4, new byte[1], HashAlgorithmName.SHA256, null!));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void VerifyData_BadRange_Throws() => WithRsa((_, rsa) =>
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            rsa.VerifyData(new byte[8], 4, 8, new byte[1], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    });

    // === Sign/verify — span overloads (the adapter's combined on-token hash+sign path) ======

    [ConditionalFact(nameof(SoftHsmAvailable))]
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

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void TrySignData_DestinationTooSmall_ReturnsFalse() => WithRsa((_, rsa) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("too small destination");
        Assert.False(rsa.TrySignData(data, new byte[8], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, out int written));
        Assert.Equal(0, written);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void TrySignData_NullPadding_Throws() => WithRsa((_, rsa) =>
        Assert.Throws<ArgumentNullException>(() =>
            rsa.TrySignData(new byte[4], new byte[256], HashAlgorithmName.SHA256, null!, out int _)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void VerifyData_Span_NullPadding_Throws() => WithRsa((_, rsa) =>
        Assert.Throws<ArgumentNullException>(() =>
            rsa.VerifyData(new byte[4].AsSpan(), new byte[256].AsSpan(), HashAlgorithmName.SHA256, null!)));

    // === Encryption / decryption ===========================================

    // OAEP-SHA1 is not gated and SoftHSM (which hardcodes SHA-1 for OAEP) supports it, so this runs.
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptDecrypt_OaepSha1_RoundTrips() => WithRsa((_, rsa) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("oaep-sha1 payload");
        byte[] ct = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA1);
        byte[] recovered = rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA1);
        Assert.Equal(plaintext, recovered);
    });

    // PKCS#1 v1.5 encryption maps to the gated CKM_RSA_PKCS, so it requires AllowInsecure.
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptDecrypt_Pkcs1_UnderAllowInsecure_RoundTrips() => WithRsa((workspace, rsa) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("pkcs1 payload");
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = rsa.Encrypt(plaintext, RSAEncryptionPadding.Pkcs1);
            byte[] recovered = rsa.Decrypt(ct, RSAEncryptionPadding.Pkcs1);
            Assert.Equal(plaintext, recovered);
        }
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Encrypt_NullArguments_Throw() => WithRsa((_, rsa) =>
    {
        Assert.Throws<ArgumentNullException>(() => rsa.Encrypt(null!, RSAEncryptionPadding.OaepSHA1));
        Assert.Throws<ArgumentNullException>(() => rsa.Encrypt(new byte[4], null!));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Decrypt_NullArguments_Throw() => WithRsa((_, rsa) =>
    {
        Assert.Throws<ArgumentNullException>(() => rsa.Decrypt(null!, RSAEncryptionPadding.OaepSHA1));
        Assert.Throws<ArgumentNullException>(() => rsa.Decrypt(new byte[4], null!));
    });

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsOaepSha256))]
    public void EncryptDecrypt_OaepSha256_RoundTrips() => WithRsa((_, rsa) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("secret payload");
        byte[] ct = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        byte[] recovered = rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA256);
        Assert.Equal(plaintext, recovered);
    });

    // === Key material export ===============================================

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportParameters_PublicOnly_ReturnsModulusAndExponent() => WithRsa((_, rsa) =>
    {
        var p = rsa.ExportParameters(includePrivateParameters: false);
        Assert.NotNull(p.Modulus);
        Assert.NotNull(p.Exponent);
        Assert.Equal(2048 / 8, p.Modulus!.Length);
        Assert.Null(p.D); // private parts must not be set
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportParameters_Private_ThrowsInsecureOperation() => WithRsa((_, rsa) =>
        Assert.Throws<InsecureOperationException>(() => rsa.ExportParameters(includePrivateParameters: true)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ImportParameters_Throws() => WithRsa((_, rsa) =>
        Assert.Throws<NotSupportedException>(() => rsa.ImportParameters(default)));

    // cross-library verification. Export the public key into a fresh BCL RSA and verify the
    // PKCS#11-produced signature — catches a DER/parameter-export bug or wrong PSS salt that a
    // same-instance round-trip would miss.
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignData_Pkcs1_VerifiesUnderBclFromExportedPublicKey() => WithRsa((_, rsa) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("cross-library verify");
        byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using var bcl = RSA.Create();
        bcl.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
        Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SignData_Pss_VerifiesUnderBclFromExportedPublicKey() => WithRsa((_, rsa) =>
    {
        byte[] data = Encoding.UTF8.GetBytes("cross-library verify");
        byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        using var bcl = RSA.Create();
        bcl.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
        Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    });
}
