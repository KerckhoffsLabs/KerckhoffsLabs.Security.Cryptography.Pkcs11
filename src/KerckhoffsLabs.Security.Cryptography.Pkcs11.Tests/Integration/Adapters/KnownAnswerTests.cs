using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>
/// BL-033: Known-answer tests (KATs) for the primary mechanisms, pinning the interop layer to
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
        finally { session.Logout(); session.CloseSession(); }
    }

    // HMAC-SHA256, RFC 4231 test case 6 (131-byte key, larger than the block size).
    internal static void Assert_HmacSha256_Kat(IPkcs11Backend backend)
    {
        byte[] key = new byte[131];
        Array.Fill(key, (byte)0xaa);
        byte[] data = System.Text.Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");
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
        finally { session.Logout(); session.CloseSession(); }
    }

    // Ed25519, RFC 8032 test 3 (2-byte message 0xaf82). Signature is deterministic, so the KAT
    // pins the exact 64 bytes; the round-trip verify also exercises the public-key import path.
    internal static void Assert_Ed25519_Kat(IPkcs11Backend backend)
    {
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
                byte[] sig = session.SignEd25519(priv, message);
                Assert.Equal(expectedSig, sig);

                session.VerifyEd25519(pub, message, expectedSig, out bool ok);
                Assert.True(ok, "RFC 8032 test 1 signature should verify against the imported public key.");

                byte[] tampered = (byte[])expectedSig.Clone();
                tampered[0] ^= 0xFF;
                session.VerifyEd25519(pub, message, tampered, out bool bad);
                Assert.False(bad, "A tampered signature must not verify.");
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        }
        finally { session.Logout(); session.CloseSession(); }
    }

    // ChaCha20-Poly1305, RFC 8439 section 2.8.2. SoftHSM does not implement this mechanism, so the
    // test is gated off there; the vector is kept ready (BCL-confirmed) for backends that support it.
    internal static void Assert_ChaCha20Poly1305_Kat(IPkcs11Backend backend)
    {
        byte[] key = H("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = H("070000004041424344454647");
        byte[] aad = H("50515253c0c1c2c3c4c5c6c7");
        byte[] pt = System.Text.Encoding.ASCII.GetBytes(
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
        finally { session.Logout(); session.CloseSession(); }
    }
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
}
