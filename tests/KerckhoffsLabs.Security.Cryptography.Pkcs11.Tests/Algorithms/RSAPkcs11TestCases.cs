using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These tests exercise the gated RSAES-PKCS#1 v1.5 / raw-RSA paths on purpose (the runtime
// secure-defaults policy check is the behaviour under test), so the compile-time warning is suppressed
// for this file only — the per-id suppression the diagnostic exists to enable.
#pragma warning disable KLPKCS11008

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic RSAPkcs11 tests: sign/verify (byte[] + span) under PKCS#1 and PSS, the key-size
/// sweep (1024 under the AllowInsecure policy, up to the OpenSSL 16384 max, BCL cross-verify best-effort),
/// OAEP encryption (SHA-1 and modern hashes), gated PKCS#1 v1.5 encryption, public-parameter export,
/// and the unsupported surface. Cases skip where the backend does not advertise the mechanism they use.
/// </summary>
internal static class RSAPkcs11TestCases
{
    private static Pkcs11Session OpenSession(IPkcs11Backend backend) =>
        backend.OpenSession();

    private static Pkcs11Key GenerateRsaKey(Pkcs11Session session, int modulusBits = 2048)
    {
        string label = $"rsa-prov-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().Encrypt().ModulusBits(modulusBits)
            .PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Decrypt().Build();

        return session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), pubTpl, privTpl);
    }

    private static void DestroyByLabel(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in session.FindKeys(filter))
        {
            k.Destroy();
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

    // Turns a token that advertises OAEP but rejects the hash parameter into a skip: SoftHSM 2.5 accepts
    // only SHA-1, and Craton HSM refuses SHA-1 (parse_oaep_hash), in C_Encrypt rather than C_EncryptInit.
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
            Assert.Skip("Token advertises OAEP but rejects this hash parameter.");
            throw; // Assert.Skip always throws; xunit.v3.assert 4.0.1 lacks [DoesNotReturn].
        }
    }

    // Generates a 2048-bit RSA key pair, wraps it as RSAPkcs11, runs the body with the session
    // (some tests need UsePolicy(CryptoPolicy.AllowInsecure)) and the adapter, then destroys both objects.
    private static void WithRsa(IPkcs11Backend backend, Action<Pkcs11Session, RSAPkcs11> body)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        using var session = OpenSession(backend);
        using var key = GenerateRsaKey(session);
        try
        {
            using var rsa = new RSAPkcs11(key);
            body(session, rsa);
        }
        finally
        {
            // Destroy only: the using disposes the wrapper as the scope unwinds, which is after this
            // block either way, so the destroy-then-dispose order is the same as when it was explicit.
            try { key.Destroy(); } catch { /* best-effort cleanup */ }
        }
    }

    // === Construction =====================================================

    internal static void Assert_Ctor_NonRsaKey_Throws(IPkcs11Backend backend)
    {
        using var session = OpenSession(backend);
        string label = $"rsa-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = session.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new RSAPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(session, label); }
    }

    // Large RSA key generation (8192/16384) is only exercised on the Linux x64 CI leg (ubuntu-latest):
    // it is slow enough on macOS / Windows / arm runners to dominate the job. The smaller sizes still
    // run everywhere, so exported-encoding and round-trip correctness keep full cross-platform coverage.
    private static bool LargeRsaKeysEnabled =>
        OperatingSystem.IsLinux() && RuntimeInformation.OSArchitecture == Architecture.X64;

    // === Key sizes: sign/verify round-trips scale with the modulus =========
    // RSA < 2048 is refused under SecureOnly (NIST SP 800-131A), so the 1024 case generates under an
    // opt-in scope; 2048+ need no opt-in. PSS-SHA256 fits even a 1024-bit modulus.
    internal static void Assert_SignVerifyData_AcrossKeySizes_RoundTrips(IPkcs11Backend backend, int modulusBits)
    {
        if (modulusBits >= 8192 && !LargeRsaKeysEnabled)
            Assert.Skip($"RSA-{modulusBits} keygen is restricted to the Linux x64 CI leg (too slow elsewhere).");

        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS_PSS);
        using var session = OpenSession(backend);
        using IDisposable? insecure = modulusBits < 2048 ? session.UsePolicy(CryptoPolicy.AllowInsecure) : null;
        using var key = GenerateRsaKey(session, modulusBits);
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
            try { key.Destroy(); } catch { /* best-effort cleanup */ }
        }
    }

    // === Sign/verify — byte[] overloads ====================================

    internal static void Assert_SignVerifyData_Pkcs1_RoundTrips(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SHA256_RSA_PKCS);
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
        backend.RequireMechanisms(CKM.CKM_SHA256_RSA_PKCS_PSS);
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

    // SHA-224 RSA PKCS#1 v1.5 signing maps to CKM_SHA224_RSA_PKCS, gated like SHA-1 (no BCL
    // HashAlgorithmName constant, no benefit over SHA-256), so it requires the AllowInsecure policy. Unlike
    // DSAPkcs11/ECDsaPkcs11, RSAPkcs11 overrides RSA's own byte[] SignData(byte[], int, int, …)
    // overload directly (see the class remarks), so the BCL's non-virtual SignData(byte[],
    // HashAlgorithmName) convenience overload reaches it without any internal BCL pre-hashing —
    // there is no non-virtual-vs-virtual split to work around here.
    internal static void Assert_SignVerifyData_Sha224Pkcs1_UnderAllowInsecure_RoundTrips(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SHA224_RSA_PKCS);
        WithRsa(backend, (session, rsa) =>
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            {
                var hash = new HashAlgorithmName("SHA224");
                byte[] data = Encoding.UTF8.GetBytes("sha224 pkcs1 payload");
                byte[] sig = rsa.SignData(data, hash, RSASignaturePadding.Pkcs1);
                Assert.True(rsa.VerifyData(data, sig, hash, RSASignaturePadding.Pkcs1));
                data[0] ^= 0xFF;
                Assert.False(rsa.VerifyData(data, sig, hash, RSASignaturePadding.Pkcs1));
            }
        });
    }

    internal static void Assert_SignData_Sha224Pkcs1_WithoutAllowInsecure_Throws(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
            Assert.Throws<CryptoPolicyViolationException>(() =>
                rsa.SignData(Encoding.UTF8.GetBytes("x"), new HashAlgorithmName("SHA224"), RSASignaturePadding.Pkcs1)));

    // Same rationale as the PKCS#1 case above, for CKM_SHA224_RSA_PKCS_PSS.
    internal static void Assert_SignVerifyData_Sha224Pss_UnderAllowInsecure_RoundTrips(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SHA224_RSA_PKCS_PSS);
        WithRsa(backend, (session, rsa) =>
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            {
                var hash = new HashAlgorithmName("SHA224");
                byte[] data = Encoding.UTF8.GetBytes("sha224 pss payload");
                byte[] sig = rsa.SignData(data, hash, RSASignaturePadding.Pss);
                Assert.True(rsa.VerifyData(data, sig, hash, RSASignaturePadding.Pss));

                byte[] tamperedSig = [.. sig];
                tamperedSig[0] ^= 0xFF;
                Assert.False(rsa.VerifyData(data, tamperedSig, hash, RSASignaturePadding.Pss));
            }
        });
    }

    internal static void Assert_SignData_Sha224Pss_WithoutAllowInsecure_Throws(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
            Assert.Throws<CryptoPolicyViolationException>(() =>
                rsa.SignData(Encoding.UTF8.GetBytes("x"), new HashAlgorithmName("SHA224"), RSASignaturePadding.Pss)));

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
        backend.RequireMechanisms(CKM.CKM_SHA256_RSA_PKCS_PSS);
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

    // OAEP with SHA-1 maps to a SHA-1-parameterized CKM_RSA_PKCS_OAEP, gated the same as any other
    // SHA-1 use, so it requires the AllowInsecure policy.
    internal static void Assert_EncryptDecrypt_OaepSha1_RoundTrips(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_OAEP);
        WithRsa(backend, (session, rsa) =>
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            {
                byte[] plaintext = Encoding.UTF8.GetBytes("oaep-sha1 payload");
                byte[] ct = OrSkipIfOaepHashUnsupported(() => rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA1));
                byte[] recovered = rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA1);
                Assert.Equal(plaintext, recovered);
            }
        });
    }

    // OAEP with SHA-224 maps to a SHA-224-parameterized CKM_RSA_PKCS_OAEP; the session's crypto policy
    // check inspects CkmRsaPkcsOaepParams.HashAlg for this one (CKM_RSA_PKCS_OAEP is a single mechanism
    // type for every hash choice), so it requires a policy that permits it the same as the SHA-1 case above.
    // RSAEncryptionPadding has no OaepSHA224 convenience property (the BCL has no SHA-224
    // HashAlgorithmName constant either), so this uses the general CreateOaep(HashAlgorithmName) factory.
    internal static void Assert_EncryptDecrypt_OaepSha224_UnderAllowInsecure_RoundTrips(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_OAEP);
        WithRsa(backend, (session, rsa) =>
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            {
                var padding = RSAEncryptionPadding.CreateOaep(new HashAlgorithmName("SHA224"));
                byte[] plaintext = Encoding.UTF8.GetBytes("oaep-sha224 payload");
                byte[] ct = OrSkipIfOaepHashUnsupported(() => rsa.Encrypt(plaintext, padding));
                byte[] recovered = rsa.Decrypt(ct, padding);
                Assert.Equal(plaintext, recovered);
            }
        });
    }

    internal static void Assert_Encrypt_OaepSha224_WithoutAllowInsecure_Throws(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
            Assert.Throws<CryptoPolicyViolationException>(() =>
                rsa.Encrypt(Encoding.UTF8.GetBytes("x"), RSAEncryptionPadding.CreateOaep(new HashAlgorithmName("SHA224")))));

    // PKCS#1 v1.5 encryption maps to the gated CKM_RSA_PKCS, so it requires the AllowInsecure policy.
    internal static void Assert_EncryptDecrypt_Pkcs1_UnderAllowInsecure_RoundTrips(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS);
        WithRsa(backend, (session, rsa) =>
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("pkcs1 payload");
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
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
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_OAEP);
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
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_OAEP);
        WithRsa(backend, (session, rsa) =>
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            {
                byte[] ct = OrSkipIfOaepHashUnsupported(
                    () => rsa.Encrypt(Encoding.UTF8.GetBytes("integrity matters"), RSAEncryptionPadding.OaepSHA1));
                ct[ct.Length / 2] ^= 0xFF; // flip one ciphertext byte

                Assert.ThrowsAny<Pkcs11Exception>(() => rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA1));
            }
        });
    }

    // A ciphertext that is not less than the modulus is no RSA ciphertext (RFC 8017 §7.1.2 and §7.2.2, step 2),
    // so it is refused as the BCL refuses it, whatever the padding. NSS answered PKCS#1 v1.5's with
    // implicit-rejection output instead until 3.132 (Bug 2079457).
    internal static void Assert_Decrypt_CiphertextNotBelowTheModulus_Throws(IPkcs11Backend backend, string padding)
    {
        backend.RequireMechanisms(padding == "Pkcs1" ? CKM.CKM_RSA_PKCS : CKM.CKM_RSA_PKCS_OAEP);
        WithRsa(backend, (session, rsa) => AssertRefusesCiphertextNotBelowTheModulus(session, rsa, padding));
    }

    // The body of Assert_Decrypt_CiphertextNotBelowTheModulus_Throws, for a token with its own key setup:
    // padding is "Pkcs1" or "Oaep" (OAEP-SHA256). The token decrypts a ciphertext the BCL made under its public
    // key before and after, so the refusal is of the value, not of the mechanism. (The BCL encrypts, since NSS
    // cannot encrypt PKCS#1 v1.5 through the library; see NssBackendFixture.SupportsRsaPkcs1Encrypt.)
    internal static void AssertRefusesCiphertextNotBelowTheModulus(Pkcs11Session session, RSAPkcs11 rsa, string padding)
    {
        RSAEncryptionPadding rsaPadding = padding == "Pkcs1" ? RSAEncryptionPadding.Pkcs1 : RSAEncryptionPadding.OaepSHA256;
        using var insecure = padding == "Pkcs1" ? session.UsePolicy(CryptoPolicy.AllowInsecure) : null;
        byte[] plaintext = Encoding.UTF8.GetBytes("below the modulus");
        byte[] ct;
        using (var publicKey = RSA.Create())
        {
            publicKey.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
            ct = publicKey.Encrypt(plaintext, rsaPadding);
        }
        Assert.Equal(plaintext, OrSkipIfOaepHashUnsupported(() => rsa.Decrypt(ct, rsaPadding)));

        using (var bcl = RSA.Create(2048))
        {
            Assert.All(NotBelowTheModulus(bcl.ExportParameters(includePrivateParameters: false).Modulus!),
                tooLarge => Assert.ThrowsAny<CryptographicException>(() => bcl.Decrypt(tooLarge, rsaPadding)));
        }
        Assert.All(NotBelowTheModulus(rsa.ExportParameters(includePrivateParameters: false).Modulus!),
            tooLarge => Assert.ThrowsAny<CryptographicException>(() => rsa.Decrypt(tooLarge, rsaPadding)));

        Assert.Equal(plaintext, rsa.Decrypt(ct, rsaPadding));
    }

    // Ciphertexts of the modulus length that are not less than the modulus: the modulus itself, and the
    // largest value of that length.
    private static IEnumerable<byte[]> NotBelowTheModulus(byte[] modulus)
    {
        yield return modulus;
        yield return Enumerable.Repeat((byte)0xFF, modulus.Length).ToArray();
    }

    internal static void Assert_Decrypt_OaepCiphertextFromDifferentKey_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_OAEP);
        WithRsa(backend, (session, rsa) =>
        {
            using Pkcs11Key other = GenerateRsaKey(session);
            try
            {
                using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                {
                    using var otherRsa = new RSAPkcs11(other);
                    byte[] ct = OrSkipIfOaepHashUnsupported(
                        () => otherRsa.Encrypt(Encoding.UTF8.GetBytes("for the other key"), RSAEncryptionPadding.OaepSHA1));

                    // About half the time the other key's ciphertext is not below this key's modulus, and the
                    // adapter refuses it before the token does.
                    Assert.ThrowsAny<CryptographicException>(() => rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA1));
                }
            }
            finally
            {
                try { other.Destroy(); } catch { /* best-effort cleanup of the second key */ }
            }
        });
    }

    // === A ciphertext the key cannot have produced =========================
    // As for the BCL's own RSA, a ciphertext must be the modulus's length and its value below the modulus; one
    // that is not throws CryptographicException without reaching the token. Some tokens answer one with a
    // plaintext, which Wycheproof test vectors (C2SP/wycheproof) found: rsa_pkcs1_2048_test.json tcId 30 (c = n),
    // tcId 32 (an empty ciphertext) and tcId 35 (a truncated one).

    // Every RSA decryption entry point. Only Decrypt(byte[], ...) is overridden: the BCL routes the others to it.
    internal static readonly Dictionary<string, Func<RSA, byte[], RSAEncryptionPadding, byte[]>> DecryptCalls = new()
    {
        ["Decrypt(byte[])"] = (rsa, c, p) => rsa.Decrypt(c, p),
        ["Decrypt(span)"] = (rsa, c, p) => rsa.Decrypt(c.AsSpan(), p),
        ["Decrypt(span, span)"] = (rsa, c, p) =>
        {
            byte[] destination = new byte[c.Length + 512];
            return destination[..rsa.Decrypt(c.AsSpan(), destination, p)];
        },
        ["TryDecrypt"] = (rsa, c, p) =>
        {
            byte[] destination = new byte[c.Length + 512];
            Assert.True(rsa.TryDecrypt(c, destination, p, out int written));
            return destination[..written];
        },
    };

    // Ciphertexts a key cannot have produced, from its modulus and one ciphertext it did produce.
    internal static (string Name, byte[] Ciphertext)[] CiphertextsNotFromTheKey(byte[] modulus, byte[] ciphertext) =>
    [
        ("empty", []),
        ("one byte short", ciphertext[..^1]),
        ("one byte long", [0x00, .. ciphertext]),
        ("c = n", modulus),
        ("c = n + 1", PlusOne(modulus)),
        ("c = 2^k - 1", Enumerable.Repeat((byte)0xFF, modulus.Length).ToArray()),
    ];

    private static byte[] PlusOne(byte[] value)
    {
        byte[] sum = [.. value];
        for (int i = sum.Length - 1; i >= 0; i--)
        {
            sum[i] = unchecked((byte)(sum[i] + 1));
            if (sum[i] != 0)
                break;
        }
        return sum;
    }

    internal static RSAEncryptionPadding EncryptionPadding(string name) =>
        name == "Pkcs1" ? RSAEncryptionPadding.Pkcs1 : RSAEncryptionPadding.OaepSHA256;

    internal static void Assert_Decrypt_CiphertextNotFromTheKey_Throws(IPkcs11Backend backend, string paddingName)
    {
        RSAEncryptionPadding padding = EncryptionPadding(paddingName);
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, padding == RSAEncryptionPadding.Pkcs1 ? CKM.CKM_RSA_PKCS : CKM.CKM_RSA_PKCS_OAEP);
        using var session = OpenSession(backend);
        using var key = GenerateRsaKey(session);
        try
        {
            using var rsa = new RSAPkcs11(key);
            RSAParameters publicKey = rsa.ExportParameters(includePrivateParameters: false);
            using var bcl = RSA.Create(publicKey);
            byte[] plaintext = Encoding.UTF8.GetBytes("for this key only");
            byte[] ciphertext = bcl.Encrypt(plaintext, padding);
            var notFromTheKey = CiphertextsNotFromTheKey(publicKey.Modulus!, ciphertext);

            // The policy refuses PKCS#1 v1.5 before the ciphertext is looked at.
            if (padding == RSAEncryptionPadding.Pkcs1)
                Assert.All(notFromTheKey, c => Assert.Throws<CryptoPolicyViolationException>(() => rsa.Decrypt(c.Ciphertext, padding)));

            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            {
                // Only the exact type: a token's refusal would be a Pkcs11Exception.
                Assert.All(notFromTheKey, c => Assert.All(DecryptCalls.Values, decrypt =>
                    Assert.Throws<CryptographicException>(() => decrypt(rsa, c.Ciphertext, padding))));

                Assert.Equal(plaintext, OrSkipIfOaepHashUnsupported(() => rsa.Decrypt(ciphertext, padding)));
                Assert.All(DecryptCalls.Values, decrypt => Assert.Equal(plaintext, decrypt(rsa, ciphertext, padding)));

                // Pkcs11Key's own Decrypt and Unwrap check it too: the adapter is not the only way in.
                Mechanism mechanism = padding == RSAEncryptionPadding.Pkcs1
                    ? new Mechanism(CKM.CKM_RSA_PKCS)
                    : Pkcs11MechanismMap.RsaOaep(HashAlgorithmName.SHA256);
                using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Build();
                Assert.All(notFromTheKey, c =>
                {
                    Assert.Throws<CryptographicException>(() => key.Decrypt(mechanism, c.Ciphertext));
                    Assert.Throws<CryptographicException>(() => key.Unwrap(mechanism, c.Ciphertext, template));
                });
                Assert.Equal(plaintext, key.Decrypt(mechanism, ciphertext));
            }
        }
        finally
        {
            try { key.Destroy(); } catch { /* best-effort cleanup */ }
        }
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
            Assert.Throws<CryptoPolicyViolationException>(() => rsa.ExportParameters(includePrivateParameters: true)));

    internal static void Assert_ImportParameters_Throws(IPkcs11Backend backend) =>
        WithRsa(backend, (_, rsa) =>
            Assert.Throws<NotSupportedException>(() => rsa.ImportParameters(default)));

    // Cross-library verification: export the public key into a fresh BCL RSA and verify the
    // PKCS#11-produced signature — catches a DER/parameter-export bug or wrong PSS salt.
    internal static void Assert_SignData_Pkcs1_VerifiesUnderBclFromExportedPublicKey(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SHA256_RSA_PKCS);
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
        backend.RequireMechanisms(CKM.CKM_SHA256_RSA_PKCS_PSS);
        WithRsa(backend, (_, rsa) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("cross-library verify");
            byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            using var bcl = RSA.Create();
            bcl.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
            Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        });
    }

    // === Signing a digest ===================================================

    // A PSS signature over a digest (raw CKM_RSA_PKCS_PSS) verifies on the token and in the BCL, and the
    // one SignData makes over the data verifies against the digest.
    internal static void Assert_SignHash_Pss_InteropsWithSignDataAndBcl(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_PSS, CKM.CKM_SHA256_RSA_PKCS_PSS);
        WithRsa(backend, (_, rsa) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("signed over its digest");
            byte[] digest = SHA256.HashData(data);

            byte[] overDigest = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            byte[] overData = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            Assert.True(rsa.VerifyHash(digest, overDigest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            Assert.True(rsa.VerifyHash(digest, overData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            using var bcl = RSA.Create();
            bcl.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
            Assert.True(bcl.VerifyHash(digest, overDigest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        });
    }

    // PKCS#1 v1.5 over a digest is raw CKM_RSA_PKCS over the DigestInfo, judged as CKM_SHA256_RSA_PKCS,
    // so the default policy allows it; the scheme is deterministic, so the signature equals SignData's.
    internal static void Assert_SignHash_Pkcs1_UnderTheDefaultPolicy_MatchesSignData(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS, CKM.CKM_SHA256_RSA_PKCS);
        WithRsa(backend, (_, rsa) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("pkcs1 over a digest");
            byte[] digest = SHA256.HashData(data);
            byte[] overData = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            Assert.Equal(overData, rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            Assert.True(rsa.VerifyHash(digest, overData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        });
    }
}
