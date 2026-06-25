using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic RSAPkcs11 tests: sign/verify (byte[] + span) under PKCS#1 and PSS, the key-size
/// sweep (1024 behind AllowInsecure, up to the OpenSSL 16384 max, BCL cross-verify best-effort),
/// OAEP encryption (SHA-1 and modern hashes), gated PKCS#1 v1.5 encryption, public-parameter export,
/// and the unsupported surface. Cases skip where the backend does not advertise the mechanism they use.
/// </summary>
internal static class RSAPkcs11TestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.Library.OpenWorkspace(backend.TokenLabel, CKU.CKU_USER, new SecurePin(backend.UserPin.Span));

    private static void Require(IPkcs11Backend backend, params CKM[] mechanisms)
    {
        foreach (var m in mechanisms)
        {
            if (!backend.Supports(m))
                throw new SkipTestException($"Backend does not advertise {m}.");
        }
    }

    private static Pkcs11Key GenerateRsaKey(Pkcs11Workspace workspace, int modulusBits = 2048)
    {
        string label = $"rsa-prov-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().Encrypt().ModulusBits(modulusBits)
            .PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Decrypt().Build();

        return workspace.GenerateKey(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), privTpl, pubTpl);
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

    // Imports an RSA public key into the BCL, returning null when the platform crypto stack cannot
    // represent a key that large (macOS Security.framework rejects RSA-16384). Lets the cross-verify
    // run wherever it is supported without failing the large-key cases on those platforms.
    private static RSA? TryImportRsaPublicKey(RSAParameters publicParameters)
    {
        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportParameters(publicParameters);
            return rsa;
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
            return null;
        }
    }

    // Turns a token that advertises OAEP but rejects a non-SHA-1 hash parameter into a skip.
    private static byte[] OrSkipIfOaepHashUnsupported(Func<byte[]> op)
    {
        try
        {
            return op();
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue is
            CKR.CKR_MECHANISM_PARAM_INVALID or CKR.CKR_MECHANISM_INVALID or
            CKR.CKR_ARGUMENTS_BAD or CKR.CKR_FUNCTION_NOT_SUPPORTED)
        {
            throw new SkipTestException("Token advertises OAEP but rejects this hash parameter.");
        }
    }

    // Generates a 2048-bit RSA key pair, wraps it as RSAPkcs11, runs the body with the workspace
    // (some tests need AllowInsecureScope) and the adapter, then destroys both objects.
    private static void WithRsa(IPkcs11Backend backend, Action<Pkcs11Workspace, RSAPkcs11> body)
    {
        Require(backend, CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        using var workspace = OpenWorkspace(backend);
        var key = GenerateRsaKey(workspace);
        try
        {
            using var rsa = new RSAPkcs11(key);
            body(workspace, rsa);
        }
        finally
        {
            try { key.Delete(); } catch { /* best-effort cleanup */ }
            key.Dispose();
        }
    }

    // === Construction =====================================================

    internal static void Assert_Ctor_NonRsaKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
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

    // === Key sizes: sign/verify round-trips scale with the modulus =========
    // RSA < 2048 is gated behind AllowInsecure (NIST SP 800-131A), so the 1024 case generates under an
    // opt-in scope; 2048+ need no opt-in. PSS-SHA256 fits even a 1024-bit modulus.
    internal static void Assert_SignVerifyData_AcrossKeySizes_RoundTrips(IPkcs11Backend backend, int modulusBits)
    {
        Require(backend, CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS_PSS);
        using var workspace = OpenWorkspace(backend);
        using IDisposable? insecure = modulusBits < 2048 ? workspace.AllowInsecureScope() : null;
        var key = GenerateRsaKey(workspace, modulusBits);
        try
        {
            using var rsa = new RSAPkcs11(key);
            byte[] data = Encoding.UTF8.GetBytes($"rsa-{modulusBits} payload");
            byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            Assert.Equal(modulusBits / 8, sig.Length);
            Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

            var pub = rsa.ExportParameters(includePrivateParameters: false);
            Assert.Equal(modulusBits / 8, pub.Modulus!.Length);

            // Cross-verify under the BCL where the platform can import a key this large (macOS rejects
            // RSA-16384 import); the on-token round-trip above is the primary assertion.
            using (RSA? bcl = TryImportRsaPublicKey(pub))
            {
                if (bcl is not null)
                    Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            }

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(rsa.VerifyData(tampered, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        }
        finally
        {
            try { key.Delete(); } catch { /* best-effort cleanup */ }
            key.Dispose();
        }
    }

    // === Sign/verify — byte[] overloads ====================================

    internal static void Assert_SignVerifyData_Pkcs1_RoundTrips(IPkcs11Backend backend)
    {
        Require(backend, CKM.CKM_SHA256_RSA_PKCS);
        WithRsa(backend, (_, rsa) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("test");
            byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            data[0] ^= 0xFF;
            Assert.False(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        });
    }

    internal static void Assert_SignVerifyData_Pss_RoundTrips(IPkcs11Backend backend)
    {
        Require(backend, CKM.CKM_SHA256_RSA_PKCS_PSS);
        WithRsa(backend, (_, rsa) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("test");
            byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

            byte[] tamperedSig = [.. sig];
            tamperedSig[0] ^= 0xFF;
            Assert.False(rsa.VerifyData(data, tamperedSig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        });
    }

    internal static void Assert_SignData_NullArguments_Throw(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
        {
            Assert.Throws<ArgumentNullException>(() =>
                rsa.SignData((byte[])null!, 0, 0, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            Assert.Throws<ArgumentNullException>(() =>
                rsa.SignData(new byte[4], 0, 4, HashAlgorithmName.SHA256, null!));
        });

    internal static void Assert_SignData_BadRange_Throws(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
        {
            byte[] data = new byte[8];
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                rsa.SignData(data, 4, 8, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        });

    internal static void Assert_VerifyData_NullArguments_Throw(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
        {
            Assert.Throws<ArgumentNullException>(() =>
                rsa.VerifyData((byte[])null!, 0, 0, new byte[1], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            Assert.Throws<ArgumentNullException>(() =>
                rsa.VerifyData(new byte[4], 0, 4, null!, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            Assert.Throws<ArgumentNullException>(() =>
                rsa.VerifyData(new byte[4], 0, 4, new byte[1], HashAlgorithmName.SHA256, null!));
        });

    internal static void Assert_VerifyData_BadRange_Throws(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                rsa.VerifyData(new byte[8], 4, 8, new byte[1], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)));

    // === Sign/verify — span overloads (combined on-token hash+sign path) ====

    internal static void Assert_TrySignData_Span_VerifyData_Span_RoundTrips(IPkcs11Backend backend)
    {
        Require(backend, CKM.CKM_SHA256_RSA_PKCS_PSS);
        WithRsa(backend, (_, rsa) =>
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
    }

    internal static void Assert_TrySignData_DestinationTooSmall_ReturnsFalse(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("too small destination");
            Assert.False(rsa.TrySignData(data, new byte[8], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, out int written));
            Assert.Equal(0, written);
        });

    internal static void Assert_TrySignData_NullPadding_Throws(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
            Assert.Throws<ArgumentNullException>(() =>
                rsa.TrySignData(new byte[4], new byte[256], HashAlgorithmName.SHA256, null!, out int _)));

    internal static void Assert_VerifyData_Span_NullPadding_Throws(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
            Assert.Throws<ArgumentNullException>(() =>
                rsa.VerifyData(new byte[4].AsSpan(), new byte[256].AsSpan(), HashAlgorithmName.SHA256, null!)));

    // === Encryption / decryption ===========================================

    internal static void Assert_EncryptDecrypt_OaepSha1_RoundTrips(IPkcs11Backend backend)
    {
        Require(backend, CKM.CKM_RSA_PKCS_OAEP);
        WithRsa(backend, (_, rsa) =>
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("oaep-sha1 payload");
            byte[] ct = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA1);
            byte[] recovered = rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA1);
            Assert.Equal(plaintext, recovered);
        });
    }

    // PKCS#1 v1.5 encryption maps to the gated CKM_RSA_PKCS, so it requires AllowInsecure.
    internal static void Assert_EncryptDecrypt_Pkcs1_UnderAllowInsecure_RoundTrips(IPkcs11Backend backend)
    {
        Require(backend, CKM.CKM_RSA_PKCS);
        WithRsa(backend, (workspace, rsa) =>
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("pkcs1 payload");
            using (workspace.AllowInsecureScope())
            {
                byte[] ct = rsa.Encrypt(plaintext, RSAEncryptionPadding.Pkcs1);
                byte[] recovered = rsa.Decrypt(ct, RSAEncryptionPadding.Pkcs1);
                Assert.Equal(plaintext, recovered);
            }
        });
    }

    internal static void Assert_Encrypt_NullArguments_Throw(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
        {
            Assert.Throws<ArgumentNullException>(() => rsa.Encrypt(null!, RSAEncryptionPadding.OaepSHA1));
            Assert.Throws<ArgumentNullException>(() => rsa.Encrypt(new byte[4], null!));
        });

    internal static void Assert_Decrypt_NullArguments_Throw(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
        {
            Assert.Throws<ArgumentNullException>(() => rsa.Decrypt(null!, RSAEncryptionPadding.OaepSHA1));
            Assert.Throws<ArgumentNullException>(() => rsa.Decrypt(new byte[4], null!));
        });

    // Modern OAEP hashes (SHA-256/384/512). A token that hardcodes SHA-1 for OAEP rejects the hash
    // parameter, which is turned into a skip.
    internal static void Assert_EncryptDecrypt_OaepModernHash_RoundTrips(IPkcs11Backend backend, string hash)
    {
        Require(backend, CKM.CKM_RSA_PKCS_OAEP);
        WithRsa(backend, (_, rsa) =>
        {
            RSAEncryptionPadding padding = hash switch
            {
                "SHA384" => RSAEncryptionPadding.OaepSHA384,
                "SHA512" => RSAEncryptionPadding.OaepSHA512,
                _ => RSAEncryptionPadding.OaepSHA256,
            };
            byte[] plaintext = Encoding.UTF8.GetBytes("secret payload");
            byte[] ct = OrSkipIfOaepHashUnsupported(() => rsa.Encrypt(plaintext, padding));
            byte[] recovered = rsa.Decrypt(ct, padding);
            Assert.Equal(plaintext, recovered);
        });
    }

    internal static void Assert_Decrypt_TamperedOaepCiphertext_Throws(IPkcs11Backend backend)
    {
        Require(backend, CKM.CKM_RSA_PKCS_OAEP);
        WithRsa(backend, (_, rsa) =>
        {
            byte[] ct = rsa.Encrypt(Encoding.UTF8.GetBytes("integrity matters"), RSAEncryptionPadding.OaepSHA1);
            ct[ct.Length / 2] ^= 0xFF; // flip one ciphertext byte

            Assert.ThrowsAny<Pkcs11Exception>(() => rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA1));
        });
    }

    internal static void Assert_Decrypt_OaepCiphertextFromDifferentKey_Throws(IPkcs11Backend backend)
    {
        Require(backend, CKM.CKM_RSA_PKCS_OAEP);
        WithRsa(backend, (workspace, rsa) =>
        {
            Pkcs11Key other = GenerateRsaKey(workspace);
            try
            {
                using var otherRsa = new RSAPkcs11(other);
                byte[] ct = otherRsa.Encrypt(Encoding.UTF8.GetBytes("for the other key"), RSAEncryptionPadding.OaepSHA1);

                Assert.ThrowsAny<Pkcs11Exception>(() => rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA1));
            }
            finally
            {
                try { other.Delete(); } catch { /* best-effort cleanup of the second key */ }
                other.Dispose();
            }
        });
    }

    // === Key material export ===============================================

    internal static void Assert_ExportParameters_PublicOnly_ReturnsModulusAndExponent(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
        {
            var p = rsa.ExportParameters(includePrivateParameters: false);
            Assert.NotNull(p.Modulus);
            Assert.NotNull(p.Exponent);
            Assert.Equal(2048 / 8, p.Modulus!.Length);
            Assert.Null(p.D); // private parts must not be set
        });

    internal static void Assert_ExportParameters_Private_ThrowsInsecureOperation(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
            Assert.Throws<InsecureOperationException>(() => rsa.ExportParameters(includePrivateParameters: true)));

    internal static void Assert_ImportParameters_Throws(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
            Assert.Throws<NotSupportedException>(() => rsa.ImportParameters(default)));

    // Cross-library verification: export the public key into a fresh BCL RSA and verify the
    // PKCS#11-produced signature — catches a DER/parameter-export bug or wrong PSS salt.
    internal static void Assert_SignData_Pkcs1_VerifiesUnderBclFromExportedPublicKey(IPkcs11Backend backend)
    {
        Require(backend, CKM.CKM_SHA256_RSA_PKCS);
        WithRsa(backend, (_, rsa) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("cross-library verify");
            byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            using var bcl = RSA.Create();
            bcl.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
            Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        });
    }

    internal static void Assert_SignData_Pss_VerifiesUnderBclFromExportedPublicKey(IPkcs11Backend backend)
    {
        Require(backend, CKM.CKM_SHA256_RSA_PKCS_PSS);
        WithRsa(backend, (_, rsa) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("cross-library verify");
            byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            using var bcl = RSA.Create();
            bcl.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
            Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        });
    }
}
