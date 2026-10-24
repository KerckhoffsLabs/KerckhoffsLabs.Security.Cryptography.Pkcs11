using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These tests drive the gated legacy mechanisms/hashes on purpose (the secure-defaults policy check is the
// behaviour under test), so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11010

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic HMACPkcs11 tests: deterministic MACs across hash algorithms, the SHA-1-HMAC gate
/// (CKM_SHA_1_HMAC requires the AllowInsecure policy), constructor validation, and the RFC 4231 known-answer
/// vector, and the SHA-3 HMACs against the BCL and Wycheproof vectors. Cases that compute a MAC skip where the backend does not advertise the corresponding
/// CKM_*_HMAC; the constructor cases run on any backend (they throw before any token call).
/// </summary>
internal static class HMACPkcs11TestCases
{
    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static CKM HmacMechanism(string hashName) => hashName switch
    {
        "SHA1" => CKM.CKM_SHA_1_HMAC,
        "SHA256" => CKM.CKM_SHA256_HMAC,
        "SHA384" => CKM.CKM_SHA384_HMAC,
        "SHA512" => CKM.CKM_SHA512_HMAC,
        "SHA3-256" => CKM.CKM_SHA3_256_HMAC,
        "SHA3-384" => CKM.CKM_SHA3_384_HMAC,
        "SHA3-512" => CKM.CKM_SHA3_512_HMAC,
        _ => throw new ArgumentOutOfRangeException(nameof(hashName), hashName, "Unexpected HMAC hash."),
    };

    private static Pkcs11Session OpenSession(IPkcs11Backend backend) =>
        backend.OpenSession();

    private static void DestroyByLabel(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in session.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    // Generates an ephemeral generic-secret key of the given length (SoftHSM enforces a per-mechanism
    // minimum HMAC key size, so callers size the key to the digest length) and runs the body.
    private static void WithHmacKey(IPkcs11Backend backend, int keyLen, Action<Pkcs11Session, Pkcs11Key> body)
    {
        backend.RequireMechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN);
        using var session = OpenSession(backend);
        string label = $"hmac-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(keyLen).Sign().Verify().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t);
        }
        try
        {
            using var key = session.OpenKey(label);
            body(session, key);
        }
        finally { DestroyByLabel(session, label); }
    }

    private static void WithImportedHmacKey(IPkcs11Backend backend, byte[] rawKey, Action<Pkcs11Key> body)
    {
        using var session = OpenSession(backend);
        string label = $"hmac-kat-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(rawKey).Sign().Verify().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = session.ImportKey(tpl);
            body(key);
        }
        finally { DestroyByLabel(session, label); }
    }

    internal static void Assert_ComputeHash_DeterministicForSameKeyAndInput(IPkcs11Backend backend, string hashName, int expectedLen)
    {
        backend.RequireMechanism(HmacMechanism(hashName));
        WithHmacKey(backend, expectedLen, (_, key) =>
        {
            using var hmac = new HMACPkcs11(key, new HashAlgorithmName(hashName));

            byte[] data = Encoding.UTF8.GetBytes("hmac test data");
            byte[] mac1 = hmac.ComputeHash(data);
            byte[] mac2 = hmac.ComputeHash(data);

            Assert.Equal(expectedLen, mac1.Length);
            Assert.Equal(mac1, mac2);
        });
    }

    // SHA-1 HMAC is gated by default (CKM_SHA_1_HMAC is disallowed); it requires the AllowInsecure policy. Also
    // covers the SHA1 branch of the internal hash-size mapping.
    internal static void Assert_ComputeHash_Sha1_UnderAllowInsecure_RoundTrips(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA_1_HMAC);
        WithHmacKey(backend, 20, (session, key) =>
        {
            using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA1);
            Assert.Equal(160, hmac.HashSize); // 20-byte digest reported in bits

            byte[] data = Encoding.UTF8.GetBytes("sha1 hmac");
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            {
                byte[] mac = hmac.ComputeHash(data);
                Assert.Equal(20, mac.Length);
            }
        });
    }

    // SHA-224 HMAC maps to CKM_SHA224_HMAC, gated like SHA-1 (no BCL HashAlgorithmName constant, no
    // benefit over SHA-256), so it requires the AllowInsecure policy.
    internal static void Assert_ComputeHash_Sha224_UnderAllowInsecure_RoundTrips(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA224_HMAC);
        WithHmacKey(backend, 28, (session, key) =>
        {
            using var hmac = new HMACPkcs11(key, new HashAlgorithmName("SHA224"));
            Assert.Equal(224, hmac.HashSize); // 28-byte digest reported in bits

            byte[] data = Encoding.UTF8.GetBytes("sha224 hmac");
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            {
                byte[] mac = hmac.ComputeHash(data);
                Assert.Equal(28, mac.Length);
            }
        });
    }

    internal static void Assert_ComputeHash_Sha224_WithoutAllowInsecure_Throws(IPkcs11Backend backend) =>
        WithHmacKey(backend, 28, (_, key) =>
        {
            using var hmac = new HMACPkcs11(key, new HashAlgorithmName("SHA224"));
            Assert.Throws<CryptoPolicyViolationException>(() => hmac.ComputeHash(Encoding.UTF8.GetBytes("x")));
        });

    internal static void Assert_ComputeHash_DifferentInputs_DifferDespiteReuse(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        WithHmacKey(backend, 32, (_, key) =>
        {
            using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA256);
            byte[] macA = hmac.ComputeHash(Encoding.UTF8.GetBytes("message A"));
            byte[] macB = hmac.ComputeHash(Encoding.UTF8.GetBytes("message B"));
            Assert.NotEqual(macA, macB);
        });
    }

    internal static void Assert_Ctor_UnsupportedHash_Throws(IPkcs11Backend backend) =>
        WithHmacKey(backend, 32, (_, key) =>
            Assert.Throws<NotSupportedException>(() => new HMACPkcs11(key, new HashAlgorithmName("MD5"))));

    internal static void Assert_Ctor_NoNamedHash_Throws(IPkcs11Backend backend) =>
        WithHmacKey(backend, 32, (_, key) =>
            Assert.Throws<NotSupportedException>(() => new HMACPkcs11(key, default)));

    // Known-answer test: HMAC-SHA256, RFC 4231 test case 6 (131-byte key, larger than the block size —
    // also clears SoftHSM's per-mechanism minimum key size).
    internal static void Assert_ComputeHash_HmacSha256_KnownAnswer(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        byte[] key = new byte[131];
        Array.Fill(key, (byte)0xaa);
        byte[] data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");
        byte[] expected = H("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

        WithImportedHmacKey(backend, key, k =>
        {
            using var hmac = new HMACPkcs11(k, HashAlgorithmName.SHA256);
            Assert.Equal(expected, hmac.ComputeHash(data));
        });
    }

    // (hashName, keyLength): a key of the digest length, one of exactly the block size (136 / 104 / 72 bytes),
    // and one a byte longer, which HMAC hashes first. The shortest is the digest length, as SoftHSM requires.
    public static TheoryData<string, int> Sha3KeySizes =>
    [
        ("SHA3-256", 32), ("SHA3-256", 136), ("SHA3-256", 137),
        ("SHA3-384", 48), ("SHA3-384", 104), ("SHA3-384", 105),
        ("SHA3-512", 64), ("SHA3-512", 72), ("SHA3-512", 73),
    ];

    internal static void Assert_Sha3_ComputeAndTryComputeHash_MatchBcl(IPkcs11Backend backend, string hashName, int keyLength)
    {
        backend.RequireMechanism(HmacMechanism(hashName));
        AssertSha3MatchesBcl((rawKey, body) => WithImportedHmacKey(backend, rawKey, body), hashName, keyLength);
    }

    // The body of the case above, over any way of importing the key (the managed token has no backend fixture).
    // The token's MAC is checked against the BCL only where the host has SHA-3 (not on macOS).
    internal static void AssertSha3MatchesBcl(Action<byte[], Action<Pkcs11Key>> withKey, string hashName, int keyLength)
    {
        var hash = new HashAlgorithmName(hashName);
        int macLength = Sha3MacLength(hashName);
        byte[] rawKey = RandomNumberGenerator.GetBytes(keyLength);
        byte[] data = Encoding.UTF8.GetBytes("authenticated by a SHA-3 HMAC");

        withKey(rawKey, key =>
        {
            using var hmac = new HMACPkcs11(key, hash);
            Assert.Equal(macLength * 8, hmac.HashSize);
            byte[] mac = hmac.ComputeHash(data);
            Assert.Equal(macLength, mac.Length);

            byte[] destination = new byte[macLength];
            Assert.True(hmac.TryComputeHash(data, destination, out int written));
            Assert.Equal(macLength, written);
            Assert.Equal(mac, destination);

            if (HostSupportsHmac(hashName))
                Assert.Equal(CryptographicOperations.HmacData(hash, rawKey, data), mac);
        });
    }

    private static int Sha3MacLength(string hashName) => hashName switch
    {
        "SHA3-256" => 32,
        "SHA3-384" => 48,
        "SHA3-512" => 64,
        _ => throw new ArgumentOutOfRangeException(nameof(hashName), hashName, "Unexpected SHA-3 hash."),
    };

    // Whether the host BCL can compute this HMAC: SHA-3 needs OpenSSL 3.x or Windows 11+, and macOS has none.
    internal static bool HostSupportsHmac(string hashName) => hashName switch
    {
        "SHA3-256" => HMACSHA3_256.IsSupported,
        "SHA3-384" => HMACSHA3_384.IsSupported,
        "SHA3-512" => HMACSHA3_512.IsSupported,
        _ => true,
    };

    // Wycheproof hmac_sha3_256_test.json: tcId 2 (valid, short message) and tcId 29 ("Flipped bit 0 in tag").
    // The token MAC must match the valid tag, and not the modified one; where the host has SHA-3, it must
    // also match the BCL.
    internal static void Assert_HmacSha3_256_WycheproofVectors(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA3_256_HMAC);
        AssertHmacSha3_256Vectors((rawKey, body) => WithImportedHmacKey(backend, rawKey, body));
    }

    // The body of the case above, over any way of importing the key.
    internal static void AssertHmacSha3_256Vectors(Action<byte[], Action<Pkcs11Key>> withKey)
    {
        (string Key, string Msg, string Tag, bool Valid)[] vectors =
        [
            ("8159fd15133cd964c9a6964c94f0ea269a806fd9f43f0da58b6cd1b33d189b2a", "77",
                "f709a35d41e82e36955512bf5fc1af0c1a9c580ff8fc3199bcb7454027029282", true),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000102030405060708090a0b0c0d0e0f",
                "0a7aeb9eab9b57a80d7bd0ea2726394a56144e2a0fc0b979d090c1846c14b3ed", false),
        ];

        foreach (var (keyHex, msgHex, tagHex, valid) in vectors)
        {
            byte[] rawKey = H(keyHex);
            byte[] msg = H(msgHex);
            withKey(rawKey, key =>
            {
                using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA3_256);
                byte[] mac = hmac.ComputeHash(msg);
                Assert.Equal(valid, CryptographicOperations.FixedTimeEquals(mac, H(tagHex)));
                if (HMACSHA3_256.IsSupported)
                    Assert.Equal(HMACSHA3_256.HashData(rawKey, msg), mac);
            });
        }
    }
}
