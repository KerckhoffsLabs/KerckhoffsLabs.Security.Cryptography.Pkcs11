using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

// These tests drive the gated legacy mechanisms/hashes on purpose (the secure-defaults policy check is the
// behaviour under test), so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11010

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// HMACPkcs11 over the in-process <c>ManagedSoftToken</c> — runs without SoftHSM. The token
/// computes <c>CKM_*_HMAC</c> with the BCL's <c>HMACSHA*</c> primitives, so on-token MACs are
/// cross-checked against <see cref="HMACSHA256"/>/<see cref="HMACSHA384"/>/<see cref="HMACSHA512"/>
/// and an RFC 4231 known-answer vector. Mirrors <c>HMACPkcs11Tests.SoftHsm2.cs</c>; the managed
/// token does not enforce a per-mechanism minimum key size, so key material is sized freely.
/// SHA-1 HMAC is insecure-by-default and runs only under <c>UsePolicy(CryptoPolicy.AllowInsecure)</c>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class HMACPkcs11Tests_Managed
{
    private static byte[] H(string hex) => Convert.FromHexString(hex);

    // Imports a generic-secret key with a known value and runs the body with it.
    private static void WithImportedHmacKey(byte[] rawKey, Action<Pkcs11Session, Pkcs11Key> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label($"hmac-{Guid.NewGuid():N}").Value(rawKey).Sign().Verify().Build();
        using var key = session.ImportKey(tpl);
        body(session, key);
    }

    // Generates an ephemeral generic-secret key of the given length and runs the body with it.
    private static void WithGeneratedHmacKey(int keyLen, Action<Pkcs11Session, Pkcs11Key> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label($"hmac-{Guid.NewGuid():N}").ValueLen(keyLen).Sign().Verify().Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), tpl);
        body(session, key);
    }

    private static byte[] BclHmac(string hashName, byte[] key, byte[] data) => hashName switch
    {
        "SHA1" => HMACSHA1.HashData(key, data),
        "SHA256" => HMACSHA256.HashData(key, data),
        "SHA384" => HMACSHA384.HashData(key, data),
        "SHA512" => HMACSHA512.HashData(key, data),
        _ => throw new InvalidOperationException($"unmapped hash {hashName}"),
    };

    // === Real crypto: cross-checked against the BCL =======================================

    [Theory]
    [InlineData("SHA256", 32)]
    [InlineData("SHA384", 48)]
    [InlineData("SHA512", 64)]
    public void ComputeHash_MatchesBcl_OverManagedToken(string hashName, int expectedLen)
    {
        byte[] keyBytes = RandomNumberGenerator.GetBytes(32);
        byte[] data = Encoding.UTF8.GetBytes("authenticated by a managed-token HMAC");
        byte[] expected = BclHmac(hashName, keyBytes, data);

        WithImportedHmacKey(keyBytes, (_, key) =>
        {
            using var hmac = new HMACPkcs11(key, new HashAlgorithmName(hashName));
            byte[] mac = hmac.ComputeHash(data);
            Assert.Equal(expectedLen, mac.Length);
            Assert.Equal(expectedLen * 8, hmac.HashSize);
            Assert.Equal(expected, mac);
        });
    }

    [Theory]
    [InlineData("SHA256", 32)]
    [InlineData("SHA384", 48)]
    [InlineData("SHA512", 64)]
    public void ComputeHash_DeterministicForSameKeyAndInput(string hashName, int expectedLen) =>
        WithGeneratedHmacKey(expectedLen, (_, key) =>
        {
            using var hmac = new HMACPkcs11(key, new HashAlgorithmName(hashName));

            byte[] data = Encoding.UTF8.GetBytes("hmac test data");
            byte[] mac1 = hmac.ComputeHash(data);
            byte[] mac2 = hmac.ComputeHash(data);

            Assert.Equal(expectedLen, mac1.Length);
            Assert.Equal(mac1, mac2);
        });

    // Different inputs under the same key must produce different MACs, and Initialize() (called by
    // ComputeHash) must reset the buffer so a second call does not accumulate the first input.
    [Fact]
    public void ComputeHash_DifferentInputs_DifferDespiteReuse() => WithGeneratedHmacKey(32, (_, key) =>
    {
        using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA256);
        byte[] macA = hmac.ComputeHash(Encoding.UTF8.GetBytes("message A"));
        byte[] macB = hmac.ComputeHash(Encoding.UTF8.GetBytes("message B"));
        Assert.NotEqual(macA, macB);
    });

    // Tampering the message must change the MAC; the untampered MAC still matches the BCL.
    [Fact]
    public void ComputeHash_TamperedData_DiffersFromOriginal()
    {
        byte[] keyBytes = RandomNumberGenerator.GetBytes(32);
        byte[] data = Encoding.UTF8.GetBytes("the quick brown fox");
        byte[] tampered = [.. data];
        tampered[0] ^= 0xFF;

        WithImportedHmacKey(keyBytes, (_, key) =>
        {
            using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA256);
            byte[] mac = hmac.ComputeHash(data);
            byte[] macTampered = hmac.ComputeHash(tampered);
            Assert.Equal(BclHmac("SHA256", keyBytes, data), mac);
            Assert.NotEqual(mac, macTampered);
        });
    }

    // Multi-part HashCore buffering must produce the same MAC as the one-shot path, and match the BCL.
    [Fact]
    public void ComputeHash_StreamingMatchesOneShotAndBcl()
    {
        byte[] keyBytes = RandomNumberGenerator.GetBytes(48);
        byte[] part1 = Encoding.UTF8.GetBytes("streamed ");
        byte[] part2 = Encoding.UTF8.GetBytes("in two parts");
        byte[] whole = [.. part1, .. part2];

        WithImportedHmacKey(keyBytes, (_, key) =>
        {
            using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA384);
            hmac.TransformBlock(part1, 0, part1.Length, null, 0);
            hmac.TransformFinalBlock(part2, 0, part2.Length);
            byte[] streamed = hmac.Hash!;

            Assert.Equal(BclHmac("SHA384", keyBytes, whole), streamed);
        });
    }

    // The span one-shot works like ComputeHash, into a destination of exactly the MAC size or larger,
    // and leaves the instance ready for the next computation.
    [Theory]
    [InlineData("SHA256", 32)]
    [InlineData("SHA384", 48)]
    [InlineData("SHA512", 64)]
    public void TryComputeHash_MatchesBcl_AndTheInstanceCanBeReused(string hashName, int macLen)
    {
        byte[] keyBytes = RandomNumberGenerator.GetBytes(32);
        byte[] first = Encoding.UTF8.GetBytes("first message");
        byte[] second = Encoding.UTF8.GetBytes("second message");

        WithImportedHmacKey(keyBytes, (_, key) =>
        {
            using var hmac = new HMACPkcs11(key, new HashAlgorithmName(hashName));
            byte[] exact = new byte[macLen];
            byte[] larger = new byte[macLen + 8];

            Assert.True(hmac.TryComputeHash(first, exact, out int written));
            Assert.Equal(macLen, written);
            Assert.Equal(BclHmac(hashName, keyBytes, first), exact);

            Assert.True(hmac.TryComputeHash(second, larger, out written));
            Assert.Equal(macLen, written);
            Assert.Equal(BclHmac(hashName, keyBytes, second), larger[..macLen]);
        });
    }

    // A short destination is refused before any data is taken in, so the next computation is unaffected.
    [Fact]
    public void TryComputeHash_DestinationTooSmall_ReturnsFalse_AndBuffersNothing()
    {
        byte[] keyBytes = RandomNumberGenerator.GetBytes(32);
        byte[] data = Encoding.UTF8.GetBytes("authenticated");

        WithImportedHmacKey(keyBytes, (_, key) =>
        {
            using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA256);

            Assert.False(hmac.TryComputeHash([1, 2, 3], new byte[31], out int written));
            Assert.Equal(0, written);

            Assert.Equal(BclHmac("SHA256", keyBytes, data), hmac.ComputeHash(data));
        });
    }

    // TryComputeHash checks the size before it calls TryHashFinal, so the protected override is called
    // directly here: it keeps HashAlgorithm's contract for any caller.
    [Fact]
    public void TryHashFinal_DestinationTooSmall_ReturnsFalse() => WithGeneratedHmacKey(32, (_, key) =>
    {
        using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA256);
        MethodInfo tryHashFinal = typeof(HMACPkcs11).GetMethod("TryHashFinal", BindingFlags.Instance | BindingFlags.NonPublic)!;

        // Span arguments cannot be boxed for Invoke, so the call goes through a delegate.
        var call = tryHashFinal.CreateDelegate<TryHashFinalCall>(hmac);
        bool ok = call(new byte[31], out int written);

        Assert.False(ok);
        Assert.Equal(0, written);
    });

    private delegate bool TryHashFinalCall(Span<byte> destination, out int bytesWritten);

    // A MAC of another length than the hash's is the token's fault, and is not passed off as a result.
    [Fact]
    public void TryComputeHash_TokenMacOfTheWrongLength_Throws()
    {
        var token = new ManagedSoftToken { SignatureOverride = mac => mac[..^1] };
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Sign().Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), tpl);
        using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA256);

        var ex = Assert.Throws<CryptographicException>(() => hmac.TryComputeHash([1, 2, 3], new byte[32], out _));
        Assert.Contains("31-byte HMAC", ex.Message, StringComparison.Ordinal);
    }

    // The MAC is always computed with the token key, so raw key bytes can be neither read nor substituted.
    [Fact]
    public void Key_CanNeitherBeReadNorReplaced() => WithGeneratedHmacKey(32, (_, key) =>
    {
        using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA256);

        Assert.Throws<NotSupportedException>(() => hmac.Key);
        Assert.Throws<NotSupportedException>(() => hmac.Key = new byte[32]);
    });

    // SHA-1 HMAC is insecure-by-default (CKM_SHA_1_HMAC); it requires the AllowInsecure policy. This also
    // covers the SHA1 branch of the internal hash-size mapping.
    [Fact]
    public void ComputeHash_Sha1_UnderAllowInsecure_MatchesBcl()
    {
        byte[] keyBytes = RandomNumberGenerator.GetBytes(20);
        byte[] data = Encoding.UTF8.GetBytes("sha1 hmac");

        WithImportedHmacKey(keyBytes, (session, key) =>
        {
            using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA1);
            Assert.Equal(160, hmac.HashSize); // 20-byte digest reported in bits

            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            {
                byte[] mac = hmac.ComputeHash(data);
                Assert.Equal(20, mac.Length);
                Assert.Equal(BclHmac("SHA1", keyBytes, data), mac);
            }
        });
    }

    // Known-answer test through the adapter: HMAC-SHA256, RFC 4231 test case 6 (131-byte key, larger
    // than the block size — "Test Using Larger Than Block-Size Key - Hash Key First").
    [Fact]
    public void ComputeHash_HmacSha256_KnownAnswer()
    {
        byte[] key = new byte[131];
        Array.Fill(key, (byte)0xaa);
        byte[] data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");
        byte[] expected = H("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

        WithImportedHmacKey(key, (_, k) =>
        {
            using var hmac = new HMACPkcs11(k, HashAlgorithmName.SHA256);
            Assert.Equal(expected, hmac.ComputeHash(data));
        });
    }

    // === Construction and argument validation (throw before any native call) ==============

    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new HMACPkcs11(null!, HashAlgorithmName.SHA256));

    [Fact]
    public void Ctor_UnsupportedHash_Throws() => WithGeneratedHmacKey(32, (_, key) =>
        Assert.Throws<NotSupportedException>(() => new HMACPkcs11(key, new HashAlgorithmName("MD5"))));

    [Fact]
    public void Ctor_NoNamedHash_Throws() => WithGeneratedHmacKey(32, (_, key) =>
        Assert.Throws<NotSupportedException>(() => new HMACPkcs11(key, default)));
}
