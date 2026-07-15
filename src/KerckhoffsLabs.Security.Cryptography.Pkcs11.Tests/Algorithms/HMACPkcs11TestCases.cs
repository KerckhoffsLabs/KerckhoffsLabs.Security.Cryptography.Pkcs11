using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

// These tests drive the gated legacy mechanisms/hashes on purpose (the AllowInsecure gate is the
// behaviour under test), so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11010

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic HMACPkcs11 tests: deterministic MACs across hash algorithms, the SHA-1-HMAC gate
/// (CKM_SHA_1_HMAC requires AllowInsecure), constructor validation, and the RFC 4231 known-answer
/// vector. Cases that compute a MAC skip where the backend does not advertise the corresponding
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
        _ => throw new ArgumentOutOfRangeException(nameof(hashName), hashName, "Unexpected HMAC hash."),
    };

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    private static void Require(IPkcs11Backend backend, CKM mechanism)
    {
        if (!backend.Supports(mechanism))
            throw new SkipTestException($"Backend does not advertise {mechanism}.");
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

    // Generates an ephemeral generic-secret key of the given length (SoftHSM enforces a per-mechanism
    // minimum HMAC key size, so callers size the key to the digest length) and runs the body.
    private static void WithHmacKey(IPkcs11Backend backend, int keyLen, Action<Pkcs11Workspace, Pkcs11Key> body)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"hmac-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(keyLen).Sign().Verify().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            body(workspace, key);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    private static void WithImportedHmacKey(IPkcs11Backend backend, byte[] rawKey, Action<Pkcs11Key> body)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"hmac-kat-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(rawKey).Sign().Verify().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            body(key);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_ComputeHash_DeterministicForSameKeyAndInput(IPkcs11Backend backend, string hashName, int expectedLen)
    {
        Require(backend, HmacMechanism(hashName));
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

    // SHA-1 HMAC is gated by default (CKM_SHA_1_HMAC is disallowed); it requires AllowInsecure. Also
    // covers the SHA1 branch of the internal hash-size mapping.
    internal static void Assert_ComputeHash_Sha1_UnderAllowInsecure_RoundTrips(IPkcs11Backend backend)
    {
        Require(backend, CKM.CKM_SHA_1_HMAC);
        WithHmacKey(backend, 20, (workspace, key) =>
        {
            using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA1);
            Assert.Equal(160, hmac.HashSize); // 20-byte digest reported in bits

            byte[] data = Encoding.UTF8.GetBytes("sha1 hmac");
            using (workspace.AllowInsecureScope())
            {
                byte[] mac = hmac.ComputeHash(data);
                Assert.Equal(20, mac.Length);
            }
        });
    }

    internal static void Assert_ComputeHash_DifferentInputs_DifferDespiteReuse(IPkcs11Backend backend)
    {
        Require(backend, CKM.CKM_SHA256_HMAC);
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
        Require(backend, CKM.CKM_SHA256_HMAC);
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
}
