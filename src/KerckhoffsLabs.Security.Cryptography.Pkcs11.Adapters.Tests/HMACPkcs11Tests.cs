using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Adapters.Tests;

public sealed class HMACPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new HMACPkcs11(key: null!, HashAlgorithmName.SHA256));
}

[Collection("SoftHsm")]
public sealed class HMACPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    // Generates an ephemeral generic-secret key of the given length and runs the body with the
    // workspace (some tests need AllowInsecureScope) and the opened key. SoftHSM enforces a
    // per-mechanism minimum HMAC key size, so callers size the key to the digest length.
    private void WithHmacKey(int keyLen, Action<Pkcs11Workspace, Pkcs11Key> body)
    {
        using var workspace = OpenWorkspace();
        string label = $"hmac-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(keyLen).Sign().Verify().OnToken().Build())
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

    // Imports a generic-secret key with a known value and runs the body with it.
    private void WithImportedHmacKey(byte[] rawKey, Action<Pkcs11Key> body)
    {
        using var workspace = OpenWorkspace();
        string label = $"hmac-kat-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(rawKey).Sign().Verify().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            body(key);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData("SHA256", 32)]
    [InlineData("SHA384", 48)]
    [InlineData("SHA512", 64)]
    public void ComputeHash_DeterministicForSameKeyAndInput(string hashName, int expectedLen) =>
        WithHmacKey(expectedLen, (_, key) =>
        {
            using var hmac = new HMACPkcs11(key, new HashAlgorithmName(hashName));

            byte[] data = Encoding.UTF8.GetBytes("hmac test data");
            byte[] mac1 = hmac.ComputeHash(data);
            byte[] mac2 = hmac.ComputeHash(data);

            Assert.Equal(expectedLen, mac1.Length);
            Assert.Equal(mac1, mac2);
        });

    // SHA-1 HMAC is gated by default (CKM_SHA_1_HMAC is disallowed); it requires AllowInsecure.
    // This also covers the SHA1 branch of the internal hash-size mapping.
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_Sha1_UnderAllowInsecure_RoundTrips() => WithHmacKey(20, (workspace, key) =>
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

    // Different inputs under the same key must produce different MACs, and Initialize() (called by
    // ComputeHash) must reset the buffer so a second call does not accumulate the first input.
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_DifferentInputs_DifferDespiteReuse() => WithHmacKey(32, (_, key) =>
    {
        using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA256);
        byte[] macA = hmac.ComputeHash(Encoding.UTF8.GetBytes("message A"));
        byte[] macB = hmac.ComputeHash(Encoding.UTF8.GetBytes("message B"));
        Assert.NotEqual(macA, macB);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_UnsupportedHash_Throws() => WithHmacKey(32, (_, key) =>
        Assert.Throws<NotSupportedException>(() => new HMACPkcs11(key, new HashAlgorithmName("MD5"))));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NoNamedHash_Throws() => WithHmacKey(32, (_, key) =>
        Assert.Throws<NotSupportedException>(() => new HMACPkcs11(key, default)));

    // Known-answer test through the adapter: HMAC-SHA256, RFC 4231 test case 6 (131-byte key, larger
    // than the block size — also clears SoftHSM's per-mechanism minimum key size).
    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ComputeHash_HmacSha256_KnownAnswer()
    {
        byte[] key = new byte[131];
        Array.Fill(key, (byte)0xaa);
        byte[] data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");
        byte[] expected = H("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

        WithImportedHmacKey(key, k =>
        {
            using var hmac = new HMACPkcs11(k, HashAlgorithmName.SHA256);
            Assert.Equal(expected, hmac.ComputeHash(data));
        });
    }
}
