using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>
/// Known-answer tests (KATs) for the primary mechanisms, pinning the interop layer to
/// published test vectors so marshalling regressions (IV/nonce/AAD/tag/params, signature encoding)
/// surface as wrong bytes rather than silently-passing round-trips. Expected values come from the
/// mechanism's reference vector and were independently confirmed via the BCL primitives.
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

        var session = TestKeys.OpenLoggedInSession(backend);
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
        finally { TestKeys.LogoutIfRequired(backend, session); session.CloseSession(); }
    }

    // HMAC-SHA256, RFC 4231 test case 6 (131-byte key, larger than the block size).
    internal static void Assert_HmacSha256_Kat(IPkcs11Backend backend)
    {
        byte[] key = new byte[131];
        Array.Fill(key, (byte)0xaa);
        byte[] data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");
        byte[] expected = H("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle k = TestKeys.CreateGenericSecretKey(session, key);
            try
            {
                using var mech = new Mechanism(CKM.CKM_SHA256_HMAC);
                Assert.Equal(expected, session.Sign(mech, k, data));
            }
            finally { session.DestroyObject(k); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.CloseSession(); }
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

        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle priv = TestKeys.CreateEd25519PrivateKey(session, seed);
            ObjectHandle pub = TestKeys.CreateEd25519PublicKey(session, point);
            try
            {
                using var eddsa = new Mechanism(CKM.CKM_EDDSA);
                byte[] sig = session.Sign(eddsa, priv, message);
                Assert.Equal(expectedSig, sig);

                session.Verify(eddsa, pub, message, expectedSig, out bool ok);
                Assert.True(ok, "RFC 8032 test 1 signature should verify against the imported public key.");

                byte[] tampered = (byte[])expectedSig.Clone();
                tampered[0] ^= 0xFF;
                session.Verify(eddsa, pub, message, tampered, out bool bad);
                Assert.False(bad, "A tampered signature must not verify.");
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.CloseSession(); }
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

        var session = TestKeys.OpenLoggedInSession(backend);
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
        finally { TestKeys.LogoutIfRequired(backend, session); session.CloseSession(); }
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
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle k = TestKeys.CreateGenericSecretKey(session, key);
            try
            {
                using var mech = new Mechanism(mechanism);
                Assert.Equal(expected, session.Sign(mech, k, data));
            }
            finally { session.DestroyObject(k); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.CloseSession(); }
    }

    // AES Key Wrap, RFC 3394 section 4.6 (256-bit KEK wrapping 256 bits of key data). CKM_AES_KEY_WRAP
    // is the bare RFC 3394 algorithm, so the wrapped output must equal the published vector byte-for-byte.
    internal static void Assert_AesKeyWrap_Kat(IPkcs11Backend backend)
    {
        byte[] kek = H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] keyData = H("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
        byte[] expected = H("28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21");

        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle wrappingKey = TestKeys.ImportAesWrappingKey(session, kek);
            ObjectHandle target = TestKeys.ImportExtractableAesKey(session, keyData);
            try
            {
                using var mech = new Mechanism(CKM.CKM_AES_KEY_WRAP);
                Assert.Equal(expected, session.WrapKey(mech, wrappingKey, target));
            }
            finally { session.DestroyObject(target); session.DestroyObject(wrappingKey); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.CloseSession(); }
    }

    // RSA-OAEP (SHA-1 / MGF1-SHA1) decrypt KAT: a fixed ciphertext produced for a fixed 2048-bit key
    // must decrypt to the known plaintext, pinning the OAEP parameter marshalling. SoftHSM implements
    // OAEP with SHA-1 only, so the vector uses SHA-1. (BCL-produced; OAEP encryption is randomized so a
    // decrypt KAT is the deterministic direction.)
    internal static void Assert_RsaOaep_Kat(IPkcs11Backend backend)
    {
        byte[] ct = H("2891fee133d34bea1cfe90fd7dde58eba1cf024c0d0a40dea08bc1ff4b9da8249ce010ca44a57606363a334a954177d6d9d9b29af7af9cc57d7430baa1776dcdde005baa93d17dbb097aff817f275cab23e107f1f7e53e3c8d296da0e2a6868b78da6ae22c141bff6a6fd74fa2b3b1eb25a55069e74654ecf81a05e75b13d5f33d65573ce9b43576c1942e29860ac0ef9b61c9011b0e263a22ec23cdaa320c3c7d8c15aa62225731b97f163ef049f7c886843d55b3b581372b6f6c27275d1cf9162de7c6b8631c528349c2185c79933852997a5e511156753ddf7b172a7a194cf35b4431b19dbdbbd0ec1a7cd0ae0bc9f635aec13026f1c0c4e70a652d337d4f");
        byte[] expectedPt = H("4b41543a205253412d4f4145502d53484131206d61727368616c6c696e67");

        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle priv = ImportRsaPrivateKey(session);
            try
            {
                using var oaep = new CkmRsaPkcsOaepParams(CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1);
                using var mech = new Mechanism(CKM.CKM_RSA_PKCS_OAEP, oaep);
                Assert.Equal(expectedPt, session.Decrypt(mech, priv, ct));
            }
            finally { session.DestroyObject(priv); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.CloseSession(); }
    }

    // RSA-PSS (SHA-256 / MGF1-SHA256, salt = 32) verify KAT: the token must accept a fixed published
    // signature and reject a tampered one, pinning the PSS parameter marshalling. (PSS signing is
    // randomized, so verification is the deterministic direction.)
    internal static void Assert_RsaPss_Kat(IPkcs11Backend backend)
    {
        byte[] msg = H("4b41543a205253412d5053532d534841323536206d61727368616c6c696e67");
        byte[] sig = H("5df789229891d1de979a891cc2c6e2bae087d4d0b4b59773e2a613e31c56043caa844b67e9b6de99029ee5eb85c56d1eab65793cca81f218ae0ed3ead217b4b3e1f88fab2f72c51d799c5f8221dab8bdf446bfe6259d5b4bbd87536f038a4d3613fefd4f86568be75f7e8c4fbc65372695e2e77c3805423aeb57c50424cb8abc0a7c3ac9458a582bf3d37d0aeb398010dd83707645f0869b3adc865783aeb0ba121cda9596d3f287798279bff2495b87a99ca01a906dc121dc57a2733a0be22b4fc4586eda26c85d987f12b553fe954a42caba73d05a6605081259be0f3d10425608beb231b8669977c605ed87363626d5b4235c3cfabc9c7c029746fdc1b54c");

        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle pub = TestKeys.ImportRsaPublicKey(session, RsaModulus, RsaPublicExponent);
            try
            {
                using var pss = new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32);
                using var mech = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, pss);
                session.Verify(mech, pub, msg, sig, out bool ok);
                Assert.True(ok, "RFC 8017 RSA-PSS signature should verify under the imported public key.");

                byte[] tampered = (byte[])sig.Clone();
                tampered[0] ^= 0xFF;
                session.Verify(mech, pub, msg, tampered, out bool bad);
                Assert.False(bad, "A tampered RSA-PSS signature must not verify.");
            }
            finally { session.DestroyObject(pub); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.CloseSession(); }
    }

    // ECDSA P-256 verify KAT over a fixed hash. CKM_ECDSA takes the raw signature as r‖s (P1363, no DER),
    // so a passing verify pins that fixed-width concatenation marshalling; a tampered sig must fail.
    internal static void Assert_EcdsaP256_Kat(IPkcs11Backend backend)
    {
        byte[] qx = H("bf0fae3d9cab8886477c5f968aed4b2931c6fbc1fa995a5f4418f174ce3ac49b");
        byte[] qy = H("9b5b0abee5fd0f0078c90d620b26f1d560bcfbdbac280ff4c3bc9aafb5b10613");
        byte[] hash = H("151606195ca4c477eca06906104edce10627489ed3b69b5789d080362af5cbf8");
        byte[] sig = H("6dffab28a14958c6cc3bc85cd55b63bf7dc33a671d001cc60b7f788841082928eb026507951d5c65c198c6996735a599ed3c51022af4840656d90b83a764a406");

        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle pub = TestKeys.ImportEcP256PublicKey(session, qx, qy);
            try
            {
                using var mech = new Mechanism(CKM.CKM_ECDSA);
                session.Verify(mech, pub, hash, sig, out bool ok);
                Assert.True(ok, "ECDSA P-256 signature should verify under the imported public key.");

                byte[] tampered = (byte[])sig.Clone();
                tampered[0] ^= 0xFF;
                session.Verify(mech, pub, hash, tampered, out bool bad);
                Assert.False(bad, "A tampered ECDSA signature must not verify.");
            }
            finally { session.DestroyObject(pub); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.CloseSession(); }
    }

    // ECDH P-256 derive KAT (CKD_NULL → raw shared secret Z). Pins the CK_ECDH1_DERIVE_PARAMS peer-point
    // marshalling: importing a fixed private scalar and deriving against a fixed peer point must yield
    // the known Z (SP 800-56A ECC CDH). The ephemeral derived secret is read then destroyed.
    internal static void Assert_EcdhP256_Kat(IPkcs11Backend backend)
    {
        byte[] privScalar = H("9428d7f39f5a4da29e1b5d58913961d8e104af34c0334e8ec08899a3fd5b8b67");
        byte[] peerX = H("5e587250eb1e96f4374b119399d529c3272e530ca679be3105820570a3f6bb38");
        byte[] peerY = H("ec9add0f07b0315110793e437934ae1835015713f0b30a7312213d7f9a494cdc");
        byte[] expectedZ = H("05c83b263aef2b5648428467f18a7e2bb566a5a77ef5a1732cc13fedca838b71");

        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle priv = TestKeys.ImportEcP256PrivateKey(session, privScalar);
            try
            {
                using var p = new CkmEcdh1DeriveParams(CKD.CKD_NULL, TestKeys.DerEcPoint(peerX, peerY));
                using var mech = new Mechanism(CKM.CKM_ECDH1_DERIVE, p);

                using var dc = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                using var dt = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
                using var dvl = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
                using var dtok = new ObjectAttribute(CKA.CKA_TOKEN, false);
                using var dext = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
                using var dsens = new ObjectAttribute(CKA.CKA_SENSITIVE, false);

                // enforceSecureDefaults: false — deliberately derive an ephemeral extractable secret to
                // read CKA_VALUE for the KAT, then destroy it (the library's own ECDH helper does the same).
                ObjectHandle derived = session.DeriveKey(
                    mech, priv, [dc, dt, dvl, dtok, dext, dsens], enforceSecureDefaults: false);
                try
                {
                    var attrs = session.GetAttributeValue(derived, [CKA.CKA_VALUE]);
                    try { Assert.Equal(expectedZ, attrs[0].GetValueAsByteArray()); }
                    finally { foreach (var a in attrs) a.Dispose(); }
                }
                finally { session.DestroyObject(derived); }
            }
            finally { session.DestroyObject(priv); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.CloseSession(); }
    }

    // Fixed 2048-bit RSA key (BCL-generated) shared by the RSA-OAEP and RSA-PSS KATs.
    private static readonly byte[] RsaModulus = H("e4daddcca4cc007891cc71c153c95f2c94407dc07ac0fffce5af7a35cea05d97475c764430289f697cfd7388440c601d50bde1a233e63ba0bc59e99549c226a503d9980e19af85a6252a75c05c3086a9b0f36965e6c672301baf69a4e9a9c85f926d434860551dccedde0f138d24a7c6058aaaa79506633000f5930e736b036739973c8ff975de17bc89fe43fb109bcce1f08a020671b1b5acb67a51a301b942d2e5d013f20ef83e4f2244da2b95d93d1ae377ac924a861c2689e2696f1d214634f6205ec3193bb2d17aafc3dcc50ddc5b7fe12ad6172e8ee3742dc5115c7114508d0acadd2730121d041959cc18775c3d3f2d1f863a33edf98d04d6d4f51737");
    private static readonly byte[] RsaPublicExponent = H("010001");

    private static ObjectHandle ImportRsaPrivateKey(Pkcs11Session session) => TestKeys.ImportRsaPrivateKey(
        session,
        RsaModulus,
        RsaPublicExponent,
        privateExponent: H("03ce2a78d3c34a024112aeedb2fb271853b4bef8b41937124f69b6aaedd683cccd6d3bf8328592663ce877f93593d7417312498410d3b41aa8122fbdda169eb643f2c6dfc125d05a9914258c3f2af38cbcdcb121279a295dada65327cce08a58e6a235ef00e2c0d1ad6667e3d8fd3c01661e1d1d52792823c0c7197f3b0e273492408102b209cb063cadcb6b86fe78627b916d35be847fb5669a9256576f98081892294d6eb226bbb752df9ce518c5a2c5b20c40fb4dce844a7f02cb2dc8200bb6c156ed047cc26a898347e77200ed75a59b210693e404ea4cde0156d74555f79e6fb44668c0fa09afaca9c11bf9913da7ff0b82be667ee63af8c2923a0ec87d"),
        prime1: H("ffef891cd4299e95cac4b90b358588a5429b027b4d0c4849eb604cf36459983ff5fc1a702c882c2682f78754de7cc611e15bcdb45d4cb7cdb4a6be1fe3d2e8551e2f4b57391e030bd7fbab4c1b255bf0d48633a8aa9a16ea2d4a9b530e96ff0d5759d95c9d208479b6c51ff7694fe1301e3c90410da8b715ce3312cd3c09927d"),
        prime2: H("e4e996b4dde4ce1d836c3f9b80eb82d3476c42a9dac7701cd473f6740bd6b91d1ad13799d9e1b81315f272540b8d553bfd2708800128edc5977784299ab4873e83cff835f27702c929c516a3998707291b2e70d07693c0e8eaad393ad537ec168bc7147da16fb8398392fbe53a55f2f0c41efb771049e93e4375c60085ca2ac3"),
        exponent1: H("33627e5ee161f1cb1548e5f6102add4280daea66a3138238051ff2933364a1a2c5da75dc6bb47358d016ae7f25a45b881f7cf511ef6185cdb125812a99ed306456891c5148d073c01eff12675753eadfb16bb85776d9351c93375574198bcb6d7c4a37cfd6643ef4c8f34ef5b7992817271af5c379e093d1b6f29e25c2961169"),
        exponent2: H("7f8908f711dd655c9a1918432a0b8ca2ebdb0c3517f81fa560548f4dce3ebe79d1b418b735e605295503f3e0916317c6c95f12e44641285ffae892909f69cf23ec4a552eb13ccf27868710faeb1188d2c51b15ad7f3308ba7bed30c26f82ad9d4e1907788b15f45cceca785f192643a9128b746cbc7d815eb83508b0c7d98003"),
        coefficient: H("394c177e4c3963473d40b7ee666201d0d1af223da40d194e8dc7ece409b4d3ecfe2ceef2fc1c7a15f9b0edc02425d3069ee6075ecc2ab59841a756c90f6e557dfe4bba8034df499ad20cffa12f7629eec7ba27190127c005008625c3b09cf64cda1997570948d51bb829672903e12981722a851d14e8a33d41d75a9ca031f707"));
}

[Collection("SoftHsm")]
public sealed class KnownAnswerTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;
    public static bool SoftHsmSupportsChaCha20Poly1305 => SoftHsmBackendFixture.SoftHsmSupportsChaCha20Poly1305;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesGcm_Kat() => KnownAnswerTestCases.Assert_AesGcm_Kat(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void HmacSha256_Kat() => KnownAnswerTestCases.Assert_HmacSha256_Kat(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ed25519_Kat() => KnownAnswerTestCases.Assert_Ed25519_Kat(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable), nameof(SoftHsmSupportsChaCha20Poly1305))]
    public void ChaCha20Poly1305_Kat() => KnownAnswerTestCases.Assert_ChaCha20Poly1305_Kat(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void HmacSha384_Kat() => KnownAnswerTestCases.Assert_HmacSha384_Kat(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void HmacSha512_Kat() => KnownAnswerTestCases.Assert_HmacSha512_Kat(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesKeyWrap_Kat() => KnownAnswerTestCases.Assert_AesKeyWrap_Kat(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaOaep_Kat() => KnownAnswerTestCases.Assert_RsaOaep_Kat(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaPss_Kat() => KnownAnswerTestCases.Assert_RsaPss_Kat(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EcdsaP256_Kat() => KnownAnswerTestCases.Assert_EcdsaP256_Kat(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EcdhP256_Kat() => KnownAnswerTestCases.Assert_EcdhP256_Kat(_backend);
}
