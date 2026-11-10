using System.Buffers.Binary;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// AES-ECB/CBC/CTR, DES and Triple-DES are unauthenticated or retired, and gated by default. They are what the
// published block-cipher vectors exercise; the warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>
/// Known-answer tests (KATs) for the primary mechanisms, pinning the interop layer to
/// published test vectors so marshalling regressions (IV/nonce/AAD/tag/params, signature encoding)
/// surface as wrong bytes rather than silently-passing round-trips. Expected values come from the
/// mechanism's reference vector, named next to each case down to its test number, and were independently
/// confirmed (with the BCL primitives, or OpenSSL where the BCL lacks the primitive).
/// </summary>
internal static class KnownAnswerTestCases
{
    private static byte[] H(string hex) => Convert.FromHexString(hex);

    // AES-GCM, McGrew & Viega test case 16 (256-bit key, 96-bit IV, with AAD).
    internal static void Assert_AesGcm_Kat(IPkcs11Backend backend)
    {
        byte[] key = H("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] iv = H("cafebabefacedbaddecaf888");
        byte[] aad = H("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        byte[] pt = H("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        byte[] expected = H(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662" +
            "76fc6ece0f4e1768cddf8853bb2d551b");

        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle k = TestKeys.CreateAes256Key(session, key);
            try
            {
                byte[] ctAndTag = TestAesGcm.Encrypt(session, k, iv, pt, aad);
                Assert.Equal(expected, ctAndTag);
                Assert.Equal(pt, TestAesGcm.Decrypt(session, k, iv, ctAndTag, aad));
            }
            finally { session.DestroyObject(k); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // The same vector, encrypted and decrypted in pieces through C_EncryptUpdate / C_DecryptUpdate. A
    // token holds back the last 16 bytes of the ciphertext as the possible tag, so multipart decryption
    // has to track which input it has consumed across calls. Pieces longer than the tag are the hard
    // case: Kryoptic before 5f1e7e6 decrypted them wrongly.
    internal static void Assert_AesGcm_Multipart_Kat(IPkcs11Backend backend)
    {
        byte[] key = H("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] iv = H("cafebabefacedbaddecaf888");
        byte[] aad = H("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        byte[] pt = H("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        byte[] expected = H(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662" +
            "76fc6ece0f4e1768cddf8853bb2d551b");

        if (!backend.SupportsMultipartAesGcm)
            Assert.Skip("Backend runs CKM_AES_GCM single-part only.");
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle k = TestKeys.CreateAes256Key(session, key);
            try
            {
                foreach (int chunk in (int[])[16, 17, 32, 64])
                    AssertRoundTrip(chunk);
            }
            finally { session.DestroyObject(k); }

            void AssertRoundTrip(int chunk)
            {
                var mech = new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(iv, aad, tagBits: 128));
                using var ctOut = new MemoryStream();
                using (var ptIn = new MemoryStream(pt))
                    session.Encrypt(mech, k, ptIn, ctOut, chunk);
                Assert.True(Convert.ToHexString(expected) == Convert.ToHexString(ctOut.ToArray()),
                    $"encrypting in {chunk}-byte pieces");

                mech = new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(iv, aad, tagBits: 128));
                using var ptOut = new MemoryStream();
                using (var ctIn = new MemoryStream(expected))
                    session.Decrypt(mech, k, ctIn, ptOut, chunk);
                Assert.True(Convert.ToHexString(pt) == Convert.ToHexString(ptOut.ToArray()),
                    $"decrypting in {chunk}-byte pieces");
            }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // HMAC-SHA256, RFC 4231 test case 6 (131-byte key, larger than the block size).
    internal static void Assert_HmacSha256_Kat(IPkcs11Backend backend)
    {
        byte[] key = new byte[131];
        Array.Fill(key, (byte)0xaa);
        byte[] data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");
        byte[] expected = H("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle k = TestKeys.CreateGenericSecretKey(session, key);
            try
            {
                var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
                Assert.Equal(expected, session.Sign(mech, k, data));
            }
            finally { session.DestroyObject(k); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // Ed25519, RFC 8032 test 3 (2-byte message 0xaf82). Signature is deterministic, so the KAT
    // pins the exact 64 bytes; the round-trip verify also exercises the public-key import path.
    internal static void Assert_Ed25519_Kat(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_EDDSA);
        byte[] seed = H("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        byte[] point = H("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        byte[] message = H("af82");
        byte[] expectedSig = H(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");

        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle priv = TestKeys.CreateEd25519PrivateKey(session, seed);
            ObjectHandle pub = TestKeys.CreateEd25519PublicKey(session, point, backend.EcxPointIsDerEncoded);
            try
            {
                var eddsa = new Mechanism(CKM.CKM_EDDSA);
                byte[] sig = session.Sign(eddsa, priv, message);
                Assert.Equal(expectedSig, sig);

                bool ok = session.Verify(eddsa, pub, message, expectedSig);
                Assert.True(ok, "RFC 8032 test 1 signature should verify against the imported public key.");

                byte[] tampered = [.. expectedSig];
                tampered[0] ^= 0xFF;
                bool bad = session.Verify(eddsa, pub, message, tampered);
                Assert.False(bad, "A tampered signature must not verify.");
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // ChaCha20-Poly1305, RFC 8439 section 2.8.2. SoftHSM does not implement this mechanism, so the
    // test is gated off there; the vector is kept ready (BCL-confirmed) for backends that support it.
    internal static void Assert_ChaCha20Poly1305_Kat(IPkcs11Backend backend)
    {
        byte[] key = H("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = H("070000004041424344454647");
        byte[] aad = H("50515253c0c1c2c3c4c5c6c7");
        byte[] pt = Encoding.ASCII.GetBytes(
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        byte[] expected = H(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b6" +
            "7ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116" +
            "1ae10b594f09e26a7e902ecbd0600691");

        backend.RequireMechanism(CKM.CKM_CHACHA20_POLY1305);
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle k = TestKeys.CreateChaCha20Key(session, key);
            try
            {
                byte[] ctAndTag = TestChaCha20Poly1305.Encrypt(session, k, nonce, pt, aad);
                Assert.Equal(expected, ctAndTag);
                Assert.Equal(pt, TestChaCha20Poly1305.Decrypt(session, k, nonce, ctAndTag, aad));
            }
            finally { session.DestroyObject(k); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // HMAC-SHA384, RFC 4231 test case 6 (131-byte key, larger than the block size).
    internal static void Assert_HmacSha384_Kat(IPkcs11Backend backend)
    {
        byte[] key = new byte[131];
        Array.Fill(key, (byte)0xaa);
        byte[] data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");
        byte[] expected = H("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952");
        AssertHmacKat(backend, CKM.CKM_SHA384_HMAC, key, data, expected);
    }

    // HMAC-SHA512, RFC 4231 test case 7 (131-byte key, larger-than-block-size data).
    internal static void Assert_HmacSha512_Kat(IPkcs11Backend backend)
    {
        byte[] key = new byte[131];
        Array.Fill(key, (byte)0xaa);
        byte[] data = Encoding.ASCII.GetBytes(
            "This is a test using a larger than block-size key and a larger than block-size data. " +
            "The key needs to be hashed before being used by the HMAC algorithm.");
        byte[] expected = H("e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58");
        AssertHmacKat(backend, CKM.CKM_SHA512_HMAC, key, data, expected);
    }

    private static void AssertHmacKat(IPkcs11Backend backend, CKM mechanism, byte[] key, byte[] data, byte[] expected)
    {
        backend.RequireMechanism(mechanism);
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle k = TestKeys.CreateGenericSecretKey(session, key);
            try
            {
                var mech = new Mechanism(mechanism);
                Assert.Equal(expected, session.Sign(mech, k, data));
            }
            finally { session.DestroyObject(k); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // AES Key Wrap, RFC 3394 section 4.6 (256-bit KEK wrapping 256 bits of key data). CKM_AES_KEY_WRAP
    // is the bare RFC 3394 algorithm, so the wrapped output must equal the published vector byte-for-byte.
    internal static void Assert_AesKeyWrap_Kat(IPkcs11Backend backend)
    {
        byte[] kek = H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] keyData = H("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
        byte[] expected = H("28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21");

        backend.RequireMechanism(CKM.CKM_AES_KEY_WRAP);
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle wrappingKey = TestKeys.ImportAesWrappingKey(session, kek);
            ObjectHandle target = TestKeys.ImportExtractableAesKey(session, keyData);
            try
            {
                var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP);
                Assert.Equal(expected, session.WrapKey(mech, wrappingKey, target));
            }
            finally { session.DestroyObject(target); session.DestroyObject(wrappingKey); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // RSA-OAEP (SHA-1 / MGF1-SHA1, empty label) decrypt KAT: Wycheproof rsa_oaep_2048_sha1_mgf1sha1_test.json,
    // tcId 2 (C2SP/wycheproof e0df04e0), a 2048-bit key decrypting to 20 zero bytes. Pins the OAEP parameter
    // marshalling. SoftHSM implements OAEP with SHA-1 only, hence SHA-1. OAEP encryption is randomized, so
    // decryption is the deterministic direction.
    internal static void Assert_RsaOaep_Kat(IPkcs11Backend backend)
    {
        byte[] ct = H("8773fdde3f148ec33d4facdfba812e44001d90861c047a9eefe6c6540212795b50dd186bb7712b8448830fc1799e0543b7093e4770f301e9216922e80280e9b50582c669e3a9a4feb08ec6f5b2428dc7efbcf6fe49feb61fd2795af1c8b23acb605812c9d7586e4f48e4d758f0695b688d1b4b563067852b1ce9db5dc82aba29ab416178f616426e5d0caf3f9903de2a5beeb970af7281e7cdacaaa00662ae36fb0365c20c653b670b3e7be4b0680932f3254d48ec3505ca1547d1be27d2414a3539f405df91057f4f97aa7796d7ccb69ed553447131fbe79611756b7e564bba7d76ce9256168446b34498a2e91d9a955a8aa98a71a43d65ee60fcea39d811fe");
        byte[] expectedPt = new byte[20];

        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle priv = ImportRsaPrivateKey(session);
            try
            {
                var oaep = new CkmRsaPkcsOaepParams(CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1);
                var mech = new Mechanism(CKM.CKM_RSA_PKCS_OAEP, oaep);
                using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
                Assert.Equal(expectedPt, session.Decrypt(mech, priv, ct));
            }
            finally { session.DestroyObject(priv); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // RSA-PSS (SHA-256 / MGF1-SHA256, salt = 32) verify KAT: Wycheproof rsa_pss_2048_sha256_mgf1_32_test.json,
    // tcId 2 (C2SP/wycheproof e0df04e0), a 2048-bit key and a 20-byte zero message. The token must accept it and
    // reject a tampered one, pinning the PSS parameter marshalling. PSS signing is randomized, so verification is
    // the deterministic direction.
    internal static void Assert_RsaPss_Kat(IPkcs11Backend backend)
    {
        byte[] msg = new byte[20];
        byte[] sig = H("0658c68fe0895646056d9bca422a64fe48813b4e14f0c8c4122e56d345b6813dc6286ffde014617e351c7af0a0d2c0f285def79cb734e1e055a25fa6fddc1c07da17b4b235c637413b1849c24311fa72331f4c0458c364a4916de8619b884d7e37288fad12926fc091f4851686a04fd0a504dbce3db370663a6ea6128fea86c2ca94c63e0d34d7f2c845b5d71d9a5e544451f524a451acb85c49bba7864e0a34a48613a819caf3dfd0d510c940f1df21c3373915be1f3509a557fa4d5a4e9f273e85467961133e2482c0907386454228fb0246638616fc31bbb6fa7c2361b8035994eec69a923f4c0bb0ba8696dfe8b1400c2398d7b343fdf498b1116c8de602");

        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle pub = TestKeys.ImportRsaPublicKey(session, PssModulus, RsaPublicExponent);
            try
            {
                var pss = new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32);
                var mech = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, pss);
                bool ok = session.Verify(mech, pub, msg, sig);
                Assert.True(ok, "Wycheproof RSA-PSS tcId 2 should verify under the imported public key.");

                // The last byte, not the first: flipping the first would make the signature exceed the modulus,
                // which a token reports as a length error rather than a signature that does not verify.
                byte[] tampered = [.. sig];
                tampered[^1] ^= 0xFF;
                bool bad = session.Verify(mech, pub, msg, tampered);
                Assert.False(bad, "A tampered RSA-PSS signature must not verify.");
            }
            finally { session.DestroyObject(pub); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // ECDSA P-256 verify KAT: RFC 6979 §A.2.5, the P-256 key and its signature "With SHA-256, message =
    // "sample"" (r, s), verified over SHA-256("sample"). CKM_ECDSA takes the raw signature as r‖s (P1363, no
    // DER), so a passing verify pins that fixed-width concatenation marshalling; a tampered sig must fail.
    internal static void Assert_EcdsaP256_Kat(IPkcs11Backend backend)
    {
        byte[] qx = H("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
        byte[] qy = H("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
        byte[] hash = System.Security.Cryptography.SHA256.HashData("sample"u8);
        byte[] sig = H(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" +
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");

        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle pub = TestKeys.ImportEcP256PublicKey(session, qx, qy);
            try
            {
                var mech = new Mechanism(CKM.CKM_ECDSA);
                bool ok = session.Verify(mech, pub, hash, sig);
                Assert.True(ok, "RFC 6979 A.2.5's ECDSA P-256 / SHA-256 signature should verify under its public key.");

                byte[] tampered = [.. sig];
                tampered[0] ^= 0xFF;
                bool bad = session.Verify(mech, pub, hash, tampered);
                Assert.False(bad, "A tampered ECDSA signature must not verify.");
            }
            finally { session.DestroyObject(pub); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // ECDH P-256 derive KAT (CKD_NULL → raw shared secret Z): NIST CAVP KAS ECC CDH primitive test
    // (SP 800-56A §5.7.1.2), KAS_ECC_CDH_PrimitiveTest.txt (CAVS 14.1), [P-256] COUNT = 0: dIUT, QCAVS and ZIUT.
    // Pins the CK_ECDH1_DERIVE_PARAMS peer-point marshalling. The ephemeral derived secret is read then destroyed.
    internal static void Assert_EcdhP256_Kat(IPkcs11Backend backend)
    {
        byte[] privScalar = H("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
        byte[] peerX = H("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287");
        byte[] peerY = H("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac");
        byte[] expectedZ = H("46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b");

        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle priv = TestKeys.ImportEcP256PrivateKey(session, privScalar);
            try
            {
                var p = new CkmEcdh1DeriveParams(CKD.CKD_NULL, TestKeys.DerEcPoint(peerX, peerY));
                var mech = new Mechanism(CKM.CKM_ECDH1_DERIVE, p);

                using var dc = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                using var dt = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
                using var dvl = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
                using var dtok = new ObjectAttribute(CKA.CKA_TOKEN, false);
                using var dext = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
                using var dsens = new ObjectAttribute(CKA.CKA_SENSITIVE, false);

                // Deliberately derives an ephemeral extractable secret to read CKA_VALUE for the KAT,
                // then destroys it — the same thing the library's ECDH helper does. Extraction is
                // opted into here rather than bypassed: there is no longer a way to skip the gate.
                using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
                ObjectHandle derived = session.DeriveKey(mech, priv, [dc, dt, dvl, dtok, dext, dsens]);
                try
                {
                    using var attrs = session.GetAttributeValue(derived, [CKA.CKA_VALUE]);
                    Assert.Equal(expectedZ, attrs[0].GetValueAsByteArray());
                }
                finally { session.DestroyObject(derived); }
            }
            finally { session.DestroyObject(priv); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // The 2048-bit keys of the Wycheproof vectors: the private key of rsa_oaep_2048_sha1_mgf1sha1 for RSA-OAEP,
    // and the public key of rsa_pss_2048_sha256_mgf1_32 for RSA-PSS (both with e = 65537).
    private static readonly byte[] RsaModulus = H("bd31c7a02691d2d9587ef6a946ff788544ccadd4b2988ad62086792a6bf96c8616b4ad13317d2270b901d0fcd1d880cb8f52fb87304a5258c11b38dfeae8df670aeee7ea1d0d9df8e00e80847e41e5989ed402d44e78b30fef17b5671d3adbf8685e4dc204499ecd1863e1d5aff28a7cf66eadf31fec9236c120add13451522c647c9832a672cd64d328c1c322183f4661d09bda60b8dd5f0328da5420821424afdabb1a80c5d12763a1b0238cd89d0742bfc50b6a2fcb701d824218f9826f4f78a23a2b5aa42ace7f175376fb6cbdb2bad293ba583d4d31c6b8f9029e46b13689249855f505756e00e225a6a45a18769bd8d2b3a4acb9f1c23d3e51882561e5");
    private static readonly byte[] PssModulus = H("a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d5");
    private static readonly byte[] RsaPublicExponent = H("010001");

    private static ObjectHandle ImportRsaPrivateKey(Pkcs11SessionCore session) => TestKeys.ImportRsaPrivateKey(
        session,
        RsaModulus,
        RsaPublicExponent,
        privateExponent: H("0747d520ca9b2dfc0335cf94301140b8102fb838c92ea99917e354e25709602dc0cdef231ff26ad2dfabbc391e723072a4ef52929f3f1cf0216e44c0093030f8ac29096faef28933bc9b924287014e2e935e2145be4752ccb82cb7646271936979cab73f521eeb27855ac2a410834ae5082eb62ef6f9899ee5cbb624a8d8c04ab7edcf78fe135d0f808f63b5de6e071779bf1d9eaaf8d3ef965486f2c52625e6e57a651c7bbd0197c99c057b3860a3260c864a11b3cf22ba44de3a3b3f3117e64ebf9a91f626ebb3f3c26d1b0bb80753468d4bf6a997b28335f20ed8c384d7558360a9ae9755661fa3749846b174e6bf330e52d09941f6ccd7de5004779f9bb9"),
        prime1: H("fe3d238d376a3856d9592fd4961c17a7fb0fa39d442e9df22e7eda115c648c5cb738df89ea92d8378558d0d9c1cf3d8bff740d3743a0140a6a7523e9176c2953b2c11d7f44691cf8bec2b34fb59c649535983319488118c03118ae7445e70df466ce98671260f05d5068ce777da97e2ba84779490500ceb4ff7f62ceca9a147f"),
        prime2: H("be814af26bf3c27115bc7595d0d12a1af7713feca877ae6e6d858825eda3d192704774f42e1ae1b67f1739e8c45a0476388070fa545b7cc96b8a44003bc8d07fde73f5bcdd18268395dcc2842b5023ff14b352382607b7179a5ea330840fc45045d86e0acc4feb135f0ab9b7ce6b8eb5f5a575f2a2a8de299c0d3f506df4879b"),
        exponent1: H("61bb4cf4572e0cf44ddefc0503a34ef0b31142fb0c9fc2f5bb2be656302732d1dd590e8d6cd0002fefa1c1bf43c28fcd4668ed3fa64e5e05d700aaca4ac7b867455af924d83e73f5a7171f68efce6bd7f3df4b1d5802d069e935acb263c0bb5b8d3db3d64379624cecc12d453fd82cf9495a18649a78c1fd500e3f04715ba3af"),
        exponent2: H("6649dbe920a7a8ceb982108cd9ab857527498aae52a2b86918ab6b381a4a2cbbf94794f78b4de9c5e8a59af56d807c06d23dbcebdca1a6f62ba4f8f03b298f32294a9036d16c2739de1cc3e0ddb4d12f2479487b57882afa246c0e297daf4d94607c5e51b3f4715f5c57d0f26d867901209db02010d0a541284640a9b9f06363"),
        coefficient: H("39ec606f5c9f1f33d964606e128e9e90cff932772c5715aa759816d504efe2c46206f3379aa61d31f88e726b50dd80b8ce8558a0d7408525f58c3399ce32e239d70941f12d21e7761c043e0b02220d25ffd03571c7ae5bbd59c31f48120676f9d7c370a749d8491bdfcea01662a136c85d349b6c710fc6f6ebf8a7a79b62adc3"));

    // === Block ciphers, from NIST's published examples =======================================

    // NIST SP 800-38A Appendix F: the four-block plaintext every mode example encrypts.
    private static readonly byte[] Sp80038aPlaintext = H(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    private static readonly byte[] Sp80038aAes128Key = H("2b7e151628aed2a6abf7158809cf4f3c");
    private static readonly byte[] Sp80038aAes256Key = H("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");

    public static TheoryData<int> AesKeyBits => [128, 256];

    // AES-ECB: SP 800-38A F.1.1 (ECB-AES128.Encrypt) and F.1.5 (ECB-AES256.Encrypt).
    internal static void Assert_AesEcb_Sp80038a_Kat(IPkcs11Backend backend, int keyBits) =>
        AssertCipherKat(backend, CKK.CKK_AES, keyBits == 128 ? Sp80038aAes128Key : Sp80038aAes256Key,
            new Mechanism(CKM.CKM_AES_ECB), Sp80038aPlaintext, H(keyBits == 128
                ? "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"
                : "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7"));

    // AES-CBC: SP 800-38A F.2.1 (CBC-AES128.Encrypt) and F.2.5 (CBC-AES256.Encrypt), IV 000102...0f.
    internal static void Assert_AesCbc_Sp80038a_Kat(IPkcs11Backend backend, int keyBits) =>
        AssertCipherKat(backend, CKK.CKK_AES, keyBits == 128 ? Sp80038aAes128Key : Sp80038aAes256Key,
            new Mechanism(CKM.CKM_AES_CBC, H("000102030405060708090a0b0c0d0e0f")), Sp80038aPlaintext, H(keyBits == 128
                ? "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
                : "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"));

    // AES-CTR: SP 800-38A F.5.1 (CTR-AES128.Encrypt) and F.5.5 (CTR-AES256.Encrypt), initial counter
    // f0f1...feff, incremented over the whole 128-bit block (ulCounterBits = 128).
    internal static void Assert_AesCtr_Sp80038a_Kat(IPkcs11Backend backend, int keyBits) =>
        AssertCipherKat(backend, CKK.CKK_AES, keyBits == 128 ? Sp80038aAes128Key : Sp80038aAes256Key,
            AesCtr(128, H("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")), Sp80038aPlaintext, H(keyBits == 128
                ? "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
                : "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"));

    // NIST's TDES example values ("Examples with Intermediate Values", TDES_ECB.pdf and TDES_CBC.pdf, cited by
    // SP 800-67 Rev. 2 Appendix B): three-key TDEA, Key1 0123456789ABCDEF, Key2 23456789ABCDEF01,
    // Key3 456789ABCDEF0123, and the first two blocks' worth (32 bytes) of SP 800-38A's plaintext.
    private static readonly byte[] TdesKey = H("0123456789abcdef23456789abcdef01456789abcdef0123");
    private static readonly byte[] TdesPlaintext = Sp80038aPlaintext[..32];

    // Triple-DES ECB: TDES_ECB.pdf, ECB-TDES (Encryption), the first example.
    internal static void Assert_TripleDesEcb_Kat(IPkcs11Backend backend) =>
        AssertCipherKat(backend, CKK.CKK_DES3, TdesKey, new Mechanism(CKM.CKM_DES3_ECB), TdesPlaintext,
            H("714772f339841d34267fcc4bd2949cc3ee11c22a576a303876183f99c0b6de87"));

    // Triple-DES CBC: TDES_CBC.pdf, CBC-TDES (Encryption), the first example (IV F69F2445DF4F9B17).
    internal static void Assert_TripleDesCbc_Kat(IPkcs11Backend backend) =>
        AssertCipherKat(backend, CKK.CKK_DES3, TdesKey, new Mechanism(CKM.CKM_DES3_CBC, H("f69f2445df4f9b17")), TdesPlaintext,
            H("2079c3d53aa763e193b79e2569ab5262516570481f25b50f73c0bda85c8e0da7"));

    // Single DES ECB: NIST SP 800-20 Table A.2 (Variable Key Known Answer Test), rounds 0 and 1: keys
    // 8001010101010101 and 4001010101010101, each encrypting the zero block. Table A.2, not A.1: A.1's key
    // 0101010101010101 is a DES weak key, which a token may refuse to import.
    public static TheoryData<string, string> DesVariableKeyRounds => new()
    {
        { "8001010101010101", "95a8d72813daa94d" },
        { "4001010101010101", "0eec1487dd8c26d5" },
    };

    internal static void Assert_DesEcb_Sp80020_Kat(IPkcs11Backend backend, string key, string ciphertext) =>
        AssertCipherKat(backend, CKK.CKK_DES, H(key), new Mechanism(CKM.CKM_DES_ECB), new byte[8], H(ciphertext));

    // Imports key, encrypts plaintext under mechanism to expected, and decrypts it back. The session runs under
    // AllowInsecure for the lease's span only: these modes and ciphers are gated by default.
    private static void AssertCipherKat(IPkcs11Backend backend, CKK keyType, byte[] key, Mechanism mechanism, byte[] plaintext, byte[] expected)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType);
            using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var encrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
            using var decrypt = new ObjectAttribute(CKA.CKA_DECRYPT, true);
            using var value = new ObjectAttribute(CKA.CKA_VALUE, key);
            ObjectHandle k = session.CreateObject([cls, type, token, encrypt, decrypt, value]);
            try
            {
                using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
                Assert.Equal(expected, session.Encrypt(mechanism, k, plaintext));
                Assert.Equal(plaintext, session.Decrypt(mechanism, k, expected));
            }
            finally { session.DestroyObject(k); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // A CKM_AES_CTR mechanism: CK_AES_CTR_PARAMS is ulCounterBits (a native CK_ULONG), then the counter block.
    private static Mechanism AesCtr(ulong counterBits, byte[] counterBlock)
    {
        byte[] parameter = new byte[UnmanagedMemory.NativeULongSize + 16];
        if (UnmanagedMemory.NativeULongSize == 8)
            BinaryPrimitives.WriteUInt64LittleEndian(parameter, counterBits);
        else
            BinaryPrimitives.WriteUInt32LittleEndian(parameter, checked((uint)counterBits));
        counterBlock.CopyTo(parameter, parameter.Length - 16);
        return new Mechanism(CKM.CKM_AES_CTR, parameter);
    }
}
