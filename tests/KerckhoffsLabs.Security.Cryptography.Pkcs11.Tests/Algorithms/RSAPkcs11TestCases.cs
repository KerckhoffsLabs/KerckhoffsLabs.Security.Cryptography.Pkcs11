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
/// the SHA-3 hashes across every path that takes one, and the unsupported surface. Cases skip where the
/// backend does not advertise the mechanism they use.
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

                    Assert.ThrowsAny<Pkcs11Exception>(() => rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA1));
                }
            }
            finally
            {
                try { other.Destroy(); } catch { /* best-effort cleanup of the second key */ }
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

    // === SHA-3 ===============================================================

    private static RSASignaturePadding SignaturePadding(string padding) =>
        padding == "Pss" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

    // The combined mechanism SignData uses for the hash and padding.
    private static CKM CombinedSignMechanism(HashAlgorithmName hash, string padding) =>
        padding == "Pss" ? Pkcs11MechanismMap.RsaPssSign(hash, saltLength: -1).Type : Pkcs11MechanismMap.RsaPkcs1Sign(hash).Type;

    private static CKM Sha3DigestMechanism(string hash) => hash switch
    {
        "SHA3-256" => CKM.CKM_SHA3_256,
        "SHA3-384" => CKM.CKM_SHA3_384,
        _ => CKM.CKM_SHA3_512,
    };

    // SignData / VerifyData with a SHA-3 hash run the combined CKM_SHA3_*_RSA_PKCS(_PSS) mechanism, the token
    // hashing, on both the byte[] and span entry points. The BCL cross-check needs the host's own SHA-3.
    internal static void Assert_SignVerifyData_Sha3_RoundTrips(IPkcs11Backend backend, string hash, string padding)
    {
        var hashAlgorithm = new HashAlgorithmName(hash);
        RSASignaturePadding signaturePadding = SignaturePadding(padding);
        backend.RequireMechanisms(CombinedSignMechanism(hashAlgorithm, padding));
        WithRsa(backend, (_, rsa) =>
        {
            byte[] data = Encoding.UTF8.GetBytes($"{hash} {padding} payload");
            byte[] sig = rsa.SignData(data, hashAlgorithm, signaturePadding);
            Assert.Equal(256, sig.Length);
            Assert.True(rsa.VerifyData(data, sig, hashAlgorithm, signaturePadding));

            byte[] spanSig = new byte[256];
            Assert.True(rsa.TrySignData(data, spanSig, hashAlgorithm, signaturePadding, out int written));
            Assert.True(rsa.VerifyData(data.AsSpan(), spanSig.AsSpan(0, written), hashAlgorithm, signaturePadding));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(rsa.VerifyData(tampered, sig, hashAlgorithm, signaturePadding));

            if (SHA3_256.IsSupported)
            {
                using var bcl = RSA.Create(rsa.ExportParameters(includePrivateParameters: false));
                Assert.True(bcl.VerifyData(data, sig, hashAlgorithm, signaturePadding));
            }
        });
    }

    // SignHash / VerifyHash over a SHA-3 digest: PKCS#1 v1.5 is raw CKM_RSA_PKCS over a DigestInfo naming the
    // SHA-3 OID, PSS is raw CKM_RSA_PKCS_PSS with CKM_SHA3_* and CKG_MGF1_SHA3_*. The digest comes from the
    // token, so the case runs whether or not the host has SHA-3; the signatures interoperate with SignData's.
    internal static void Assert_SignHash_Sha3_InteropsWithSignData(IPkcs11Backend backend, string hash, string padding)
    {
        var hashAlgorithm = new HashAlgorithmName(hash);
        RSASignaturePadding signaturePadding = SignaturePadding(padding);
        backend.RequireMechanisms(
            CombinedSignMechanism(hashAlgorithm, padding),
            padding == "Pss" ? CKM.CKM_RSA_PKCS_PSS : CKM.CKM_RSA_PKCS,
            Sha3DigestMechanism(hash));
        WithRsa(backend, (session, rsa) =>
        {
            byte[] data = Encoding.UTF8.GetBytes($"{hash} {padding} over a digest");
            byte[] digest = session.Digest(new Mechanism(Sha3DigestMechanism(hash)), data);

            byte[] overData = rsa.SignData(data, hashAlgorithm, signaturePadding);
            byte[] overDigest = rsa.SignHash(digest, hashAlgorithm, signaturePadding);

            Assert.True(rsa.VerifyHash(digest, overData, hashAlgorithm, signaturePadding));
            Assert.True(rsa.VerifyData(data, overDigest, hashAlgorithm, signaturePadding));
            if (padding == "Pkcs1")
                Assert.Equal(overData, overDigest); // deterministic scheme

            byte[] tampered = [.. digest];
            tampered[0] ^= 0xFF;
            Assert.False(rsa.VerifyHash(tampered, overDigest, hashAlgorithm, signaturePadding));

            // As the BCL: a digest of the wrong length cannot be signed, and does not verify.
            Assert.Throws<CryptographicException>(() => rsa.SignHash(digest[..^1], hashAlgorithm, signaturePadding));
            Assert.False(rsa.VerifyHash(digest[..^1], overDigest, hashAlgorithm, signaturePadding));
        });
    }

    // RSA-OAEP with a SHA-3 hash and MGF1 (CKM_RSA_PKCS_OAEP naming CKM_SHA3_* / CKG_MGF1_SHA3_*). A token that
    // rejects the hash parameter is a skip; the token decrypts a BCL ciphertext where the host has SHA-3.
    internal static void Assert_EncryptDecrypt_OaepSha3_RoundTrips(IPkcs11Backend backend, string hash)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_OAEP);
        WithRsa(backend, (_, rsa) =>
        {
            var padding = RSAEncryptionPadding.CreateOaep(new HashAlgorithmName(hash));
            byte[] plaintext = Encoding.UTF8.GetBytes($"oaep-{hash} payload");
            byte[] ct = OrSkipIfOaepHashUnsupported(() => rsa.Encrypt(plaintext, padding));
            Assert.Equal(plaintext, rsa.Decrypt(ct, padding));

            if (SHA3_256.IsSupported)
            {
                using var bcl = RSA.Create(rsa.ExportParameters(includePrivateParameters: false));
                Assert.Equal(plaintext, rsa.Decrypt(bcl.Encrypt(plaintext, padding), padding));
            }
        });
    }

    // C2SP/wycheproof rsa_signature_2048_sha3_256_test.json: the group's public key, tcId 4 (valid) and tcId 24
    // ("appending 0's to digestInfo", invalid), both over the message "123400". The modulus drops the vector's
    // leading DER sign byte.
    private static readonly byte[] WycheproofSha3Modulus = Convert.FromHexString(
        "9a9978ed8968b4eeff1bba921ec7a8aff62f89c289d2a4576bed7e05ffec8af9101771f1cde3f5bcabf555021f102384" +
        "8aa2ad24f3f0c75cdc68e565e806c8fc35393c4503895e622b8e335ab8a1faddfa0a3eea79361b0662459d58887fa7d0" +
        "f320230c36f521dfea5cf13d864c4ea1811aa5953afbac29f1fcb68847640f4711c92742af9c7eca813f2e1e9e794ce3" +
        "fe5130ed5bb11be3bdf730d491fc62eb0a26b440f4bf4eb822933fa89b2b9783df06b0b725d09df9365489c30b55bdef" +
        "fada4d8c893ce32000e248c172c6e76d5db2185ddd1204b33c3a64d2723500b4912197d13304c80b93357019f3cbb778" +
        "34f88d72b3a23e214e288097213876c7");

    private static readonly byte[] WycheproofSha3Message = Convert.FromHexString("313233343030");

    private static readonly byte[] WycheproofSha3ValidSignature = Convert.FromHexString(
        "7f5159eb69ac6fc09a9c0eb3aaff7165144b103afd849b9b073e5f7788055fc62eff18e8a5a0b7e7b2ff58502b333cef" +
        "f924a991cb493c6a39a0724f1fab353475112d2318c50fe3313916dae7af496b89a15264c251cd4a1189e1fd3a794018" +
        "460f8a74227e27e3211febf5babff0ed5fb52c7dea480893198dd7dcc142ac4b231106d7441b40ce695c40d7b8de67e1" +
        "40f696a55cf73372aed00ae57e6c26a43927af9f456a67653bf3ded6be9b76b8cd4d5216eecdfd54fbcfeffc14855140" +
        "17e211c2b09dd23f0e9a42d294fbd19c9bd46500f39343969e54375342ed105045923016f3ee1f5e53bcbf5d3276928b" +
        "98df49a4ce587b8f151fe741e63cf1a1");

    private static readonly byte[] WycheproofSha3InvalidSignature = Convert.FromHexString(
        "2ce5c23ec3c369a6bbd072ad83965ffd225be9492ac501f74e20d4ef5d7d6eac13d985c2bef747e07cfcabae1d25124b" +
        "d38e66081763d012f4330c325d103fb85b34d28cec31db3cece8e28914bf9eecf5e88c3a271b48056f143077ea307f50" +
        "295308a2de7c7952f1e12128f61fd81d78af40696352d190015eaa65cf38b9f7b72b157f2f63bb62337753c65cd47e1a" +
        "c9ffe830d22ec1db75ad91d9dd5280fab9a6035cf2b2545bffc488cbf17277929bb448b9a36d3f2e657e666a951f5e92" +
        "f9a5ac2bd45dba2079a2171b7bfddd87c18633b8a5832285b3ced8a2d6067a5446e84c7c7c6039752fc049c26778b130" +
        "60b23c3af57cd6e4a4f24853dac54bfd");

    // Imports the vector's public key as a session object, runs the body with the adapter, then destroys it.
    private static void WithWycheproofSha3Key(IPkcs11Backend backend, Action<Pkcs11Session, RSAPkcs11> body)
    {
        using var session = OpenSession(backend);
        using var template = ObjectTemplate.ForPublicKey(CKK.CKK_RSA).Verify().OnToken(false)
            .Attribute(CKA.CKA_MODULUS, WycheproofSha3Modulus)
            .Attribute(CKA.CKA_PUBLIC_EXPONENT, [0x01, 0x00, 0x01])
            .Build();
        using var key = session.ImportKey(template);
        try
        {
            using var rsa = new RSAPkcs11(key);
            body(session, rsa);
        }
        finally
        {
            try { key.Destroy(); } catch { /* best-effort cleanup */ }
        }
    }

    internal static void Assert_VerifyData_Sha3_256Pkcs1_WycheproofVectors(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SHA3_256_RSA_PKCS);
        WithWycheproofSha3Key(backend, (_, rsa) =>
        {
            Assert.True(rsa.VerifyData(WycheproofSha3Message, WycheproofSha3ValidSignature, HashAlgorithmName.SHA3_256, RSASignaturePadding.Pkcs1));
            Assert.False(rsa.VerifyData(WycheproofSha3Message, WycheproofSha3InvalidSignature, HashAlgorithmName.SHA3_256, RSASignaturePadding.Pkcs1));
        });
    }

    // The same vectors through VerifyHash: the DigestInfo the adapter builds must carry the SHA3-256 OID the
    // signer used, so this pins the encoding against a signature made elsewhere.
    internal static void Assert_VerifyHash_Sha3_256Pkcs1_WycheproofVectors(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS, CKM.CKM_SHA3_256);
        WithWycheproofSha3Key(backend, (session, rsa) =>
        {
            byte[] digest = session.Digest(new Mechanism(CKM.CKM_SHA3_256), WycheproofSha3Message);
            Assert.True(rsa.VerifyHash(digest, WycheproofSha3ValidSignature, HashAlgorithmName.SHA3_256, RSASignaturePadding.Pkcs1));
            Assert.False(rsa.VerifyHash(digest, WycheproofSha3InvalidSignature, HashAlgorithmName.SHA3_256, RSASignaturePadding.Pkcs1));
        });
    }
}
