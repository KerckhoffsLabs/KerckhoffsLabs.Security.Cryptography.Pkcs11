using System.Security.Cryptography;
using CsCheck;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.PropertyBased;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms.PropertyTestSupport;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Differential tests of the <c>Algorithms</c> adapters, with the BCL as the oracle: each property draws
/// keys, data, nonces and lengths from CsCheck generators (<see cref="CsInputs"/>), weighted toward the
/// boundary lengths. The laws an adapter keeps without an oracle are <see cref="AlgorithmLawTestCases"/>'s,
/// on FsCheck. A deterministic algorithm must give the BCL's bytes exactly;
/// this file holds those. A randomized one (signatures, key agreement) must interoperate with the BCL
/// both ways the token's keys allow; <c>BclDifferentialTestCases.Asymmetric.cs</c> holds those.
/// </summary>
/// <remarks>
/// <para>
/// The properties use only inputs the algorithm accepts: the BCL produces every ciphertext the token
/// decrypts, so no token is handed a malformed one. They cover every adapter except the legacy ones
/// (MD5, SHA-1, DES, 3DES, RC2, DSA), which keep their example-based tests. The unauthenticated AES
/// modes (CBC, CFB), which the default policy refuses, run under an explicit opt-in; CCM tags stay at
/// the 64 bits or more the policy requires.
/// </para>
/// <para>
/// Theory parameters pick the algorithm and are gated before the property runs, on the mechanism the
/// backend advertises and on what the host BCL supports (SHA-3 and ChaCha20-Poly1305 need OpenSSL 3 or
/// a recent Windows). The generators pick everything else. Every key is imported fresh for its case, so
/// no key and IV pair repeats (Craton HSM refuses a repeated IV under the same key value).
/// </para>
/// </remarks>
internal static partial class BclDifferentialTestCases
{
    // === Hashes ============================================================================

    // One-shot, span and three-part streamed digests all equal the BCL's, on one reused instance.
    // emptyData false leaves the empty message out, for a token that refuses to digest it.
    internal static void Assert_Digest_MatchesBcl(IPkcs11Backend backend, string hashName, bool emptyData = true)
    {
        HashSpec spec = Hash(hashName);
        backend.RequireMechanism(spec.Digest);
        RequireHost(spec.HostSupportsHash(), $"Host BCL has no {hashName}.");

        using var session = backend.OpenSession();
        using HashAlgorithm sha = spec.Create(session);
        byte[] destination = new byte[spec.Size];

        CsInputs.Check(CsInputs.Chunked(maxLength: 2048, minLength: emptyData ? 0 : 1), input =>
        {
            byte[] expected = spec.Hash(input.Data);

            Assert.Equal(expected, sha.ComputeHash(input.Data));

            Assert.True(sha.TryComputeHash(input.Data, destination, out int written));
            Assert.Equal(spec.Size, written);
            Assert.Equal(expected, destination);

            sha.TransformBlock(input.Data, 0, input.First, null, 0);
            sha.TransformBlock(input.Data, input.First, input.Second - input.First, null, 0);
            sha.TransformFinalBlock(input.Data, input.Second, input.Data.Length - input.Second);
            Assert.Equal(expected, sha.Hash);
        });
    }

    // An HMAC under a key of any length from the digest size (SoftHSM's minimum) to twice the block size
    // (the token hashes a key longer than a block first), one-shot and streamed.
    internal static void Assert_Hmac_MatchesBcl(IPkcs11Backend backend, string hashName)
    {
        HashSpec spec = Hash(hashName);
        backend.RequireMechanism(spec.Hmac);
        RequireHost(spec.HostSupportsHmac(), $"Host BCL has no HMAC over {hashName}.");

        using var session = backend.OpenSession();
        var inputs =
            from key in CsInputs.Bytes(spec.Size, 2 * spec.BlockSize)
            from data in CsInputs.Chunked(maxLength: 2048)
            select (key, data);

        CsInputs.Check(inputs, input =>
        {
            byte[] expected = spec.HashHmac(input.key, input.data.Data);

            WithSecretKey(backend, session, CKK.CKK_GENERIC_SECRET, input.key, b => b.Sign().Verify(), key =>
            {
                using var hmac = new HMACPkcs11(key, new HashAlgorithmName(hashName));
                Assert.Equal(expected, hmac.ComputeHash(input.data.Data));

                hmac.TransformBlock(input.data.Data, 0, input.data.First, null, 0);
                hmac.TransformBlock(input.data.Data, input.data.First, input.data.Second - input.data.First, null, 0);
                hmac.TransformFinalBlock(input.data.Data, input.data.Second, input.data.Data.Length - input.data.Second);
                Assert.Equal(expected, hmac.Hash);
            });
        });
    }

    // === AES ===============================================================================

    private static readonly Gen<byte[]> AesKey = Gen.OneOfConst(16, 24, 32).SelectMany(CsInputs.Bytes);

    // CBC with and without PKCS#7 padding: the token's ciphertext is the BCL's, and the token decrypts
    // the BCL's ciphertext back to the plaintext. Without padding the plaintext is whole blocks. The
    // default policy refuses an unauthenticated mode; this property opts in for its session.
    internal static void Assert_AesCbc_MatchesBcl(IPkcs11Backend backend, PaddingMode padding)
    {
        backend.RequireMechanism(padding == PaddingMode.PKCS7 ? CKM.CKM_AES_CBC_PAD : CKM.CKM_AES_CBC);

        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var inputs =
            from key in AesKey
            from iv in CsInputs.Bytes(16)
            from data in padding == PaddingMode.None ? CsInputs.Blocks(16, 1, 64) : CsInputs.Bytes(0, 1024)
            select (key, iv, data);

        CsInputs.Check(inputs, input =>
        {
            using Aes bcl = BclAes(input.key);
            byte[] expected = bcl.EncryptCbc(input.data, input.iv, padding);

            WithAes(backend, session, input.key, aes =>
            {
                Assert.Equal(expected, aes.EncryptCbc(input.data, input.iv, padding));
                Assert.Equal(input.data, aes.DecryptCbc(expected, input.iv, padding));
            });
        });
    }

    // CFB8 takes any length; CFB128 without padding takes whole blocks, as the BCL requires. Opted in
    // like CBC.
    internal static void Assert_AesCfb_MatchesBcl(IPkcs11Backend backend, int feedbackSizeInBits)
    {
        backend.RequireMechanism(feedbackSizeInBits == 8 ? CKM.CKM_AES_CFB8 : CKM.CKM_AES_CFB128);

        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var inputs =
            from key in AesKey
            from iv in CsInputs.Bytes(16)
            from data in feedbackSizeInBits == 8 ? CsInputs.Bytes(1, 1024) : CsInputs.Blocks(16, 1, 64)
            select (key, iv, data);

        CsInputs.Check(inputs, input =>
        {
            using Aes bcl = BclAes(input.key);
            byte[] expected = bcl.EncryptCfb(input.data, input.iv, PaddingMode.None, feedbackSizeInBits);

            WithAes(backend, session, input.key, aes =>
            {
                Assert.Equal(expected, aes.EncryptCfb(input.data, input.iv, PaddingMode.None, feedbackSizeInBits));
                Assert.Equal(input.data, aes.DecryptCfb(expected, input.iv, PaddingMode.None, feedbackSizeInBits));
            });
        });
    }

    // RFC 5649 key wrap with padding is deterministic: the token's wrap is the BCL's, and the token
    // unwraps the BCL's wrap. A token that lists the mechanism for C_WrapKey only (Craton HSM does) skips:
    // the adapter then wraps through the base class over ECB, which the default policy refuses and
    // AesPkcs11Tests covers.
    internal static void Assert_AesKeyWrapPadded_MatchesBcl(IPkcs11Backend backend)
    {
        backend.RequireMechanismFlags(CKM.CKM_AES_KEY_WRAP_KWP, f => f.Encrypt && f.Decrypt, "CKF_ENCRYPT and CKF_DECRYPT");

        using var session = backend.OpenSession();
        var inputs =
            from key in AesKey
            from data in CsInputs.Bytes(1, 512)
            select (key, data);

        CsInputs.Check(inputs, input =>
        {
            using Aes bcl = BclAes(input.key);
            byte[] expected = bcl.EncryptKeyWrapPadded(input.data);

            WithAes(backend, session, input.key, aes =>
            {
                Assert.Equal(expected, aes.EncryptKeyWrapPadded(input.data));
                Assert.Equal(input.data, aes.DecryptKeyWrapPadded(expected));
            });
        });
    }

    private static Aes BclAes(byte[] key)
    {
        var aes = Aes.Create();
        aes.Key = key;
        return aes;
    }

    private static void WithAes(IPkcs11Backend backend, Pkcs11Session session, byte[] value, Action<AesPkcs11> body) =>
        WithSecretKey(backend, session, CKK.CKK_AES, value, b => b.Encrypt().Decrypt(), key =>
        {
            using var aes = new AesPkcs11(key);
            body(aes);
        });

    // === AEAD ==============================================================================

    private sealed record AeadCase(byte[] Key, byte[] Nonce, byte[] Plaintext, byte[] AssociatedData, int TagSize)
    {
        public override string ToString() =>
            $"key {Convert.ToHexString(Key)}, nonce {Convert.ToHexString(Nonce)}, tag {TagSize} bytes, " +
            $"aad {Convert.ToHexString(AssociatedData)}, plaintext {Convert.ToHexString(Plaintext)}";
    }

    private static Gen<AeadCase> AeadCases(Gen<byte[]> key, Gen<int> nonceSize, Gen<int> tagSize) =>
        from k in key
        from nonceLength in nonceSize
        from nonce in CsInputs.Bytes(nonceLength)
        from tag in tagSize
        from aad in CsInputs.Bytes(0, 256)
        from plaintext in CsInputs.Bytes(0, 1024)
        select new AeadCase(k, nonce, plaintext, aad, tag);

    // AES-GCM, a 96-bit nonce and every tag size both the token and the host BCL take: 12 to 16 bytes
    // unless a token restricts them, and 16 only on macOS, whose AesGcm takes no other.
    internal static void Assert_AesGcm_MatchesBcl(IPkcs11Backend backend, int[]? keySizes = null, int[]? tagSizes = null)
    {
        backend.RequireMechanism(CKM.CKM_AES_GCM);
        RequireHost(AesGcm.IsSupported, "Host BCL has no AES-GCM.");
        int[] tags = [.. (tagSizes ?? [12, 13, 14, 15, 16]).Where(t => IsLegal(t, AesGcm.TagByteSizes))];
        RequireHost(tags.Length > 0, "Host BCL's AES-GCM takes none of the token's tag sizes.");

        using var session = backend.OpenSession();
        Gen<byte[]> key = keySizes is null ? AesKey : Gen.OneOfConst(keySizes).SelectMany(CsInputs.Bytes);
        CsInputs.Check(AeadCases(key, Gen.OneOfConst(12), Gen.OneOfConst(tags)), input =>
        {
            var (ciphertext, tag) = Seal(input, (c, t) =>
            {
                using var bcl = new AesGcm(input.Key, input.TagSize);
                bcl.Encrypt(input.Nonce, input.Plaintext, c, t, input.AssociatedData);
            });

            WithSecretKey(backend, session, CKK.CKK_AES, input.Key, b => b.Encrypt().Decrypt(), key =>
            {
                using var gcm = new AesGcmPkcs11(key, input.TagSize);
                AssertAeadMatches(input, ciphertext, tag, gcm.Encrypt, gcm.Decrypt);
            });
        });
    }

    // AES-CCM, every nonce size it defines (7 to 13 bytes) and every tag size the default policy allows
    // (8 to 16 bytes, even; it refuses the 4- and 6-byte tags CCM also defines).
    internal static void Assert_AesCcm_MatchesBcl(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_CCM);
        RequireHost(AesCcm.IsSupported, "Host BCL has no AES-CCM.");

        using var session = backend.OpenSession();
        var tagSize = Gen.OneOfConst(8, 10, 12, 14, 16);
        CsInputs.Check(AeadCases(AesKey, CsInputs.Int(7, 13), tagSize), input =>
        {
            var (ciphertext, tag) = Seal(input, (c, t) =>
            {
                using var bcl = new AesCcm(input.Key);
                bcl.Encrypt(input.Nonce, input.Plaintext, c, t, input.AssociatedData);
            });

            WithSecretKey(backend, session, CKK.CKK_AES, input.Key, b => b.Encrypt().Decrypt(), key =>
            {
                using var ccm = new AesCcmPkcs11(key, input.TagSize);
                AssertAeadMatches(input, ciphertext, tag, ccm.Encrypt, ccm.Decrypt);
            });
        });
    }

    internal static void Assert_ChaCha20Poly1305_MatchesBcl(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_CHACHA20_POLY1305);
        RequireHost(ChaCha20Poly1305.IsSupported, "Host BCL has no ChaCha20-Poly1305.");

        using var session = backend.OpenSession();
        CsInputs.Check(AeadCases(CsInputs.Bytes(32), Gen.OneOfConst(12), Gen.OneOfConst(16)), input =>
        {
            var (ciphertext, tag) = Seal(input, (c, t) =>
            {
                using var bcl = new ChaCha20Poly1305(input.Key);
                bcl.Encrypt(input.Nonce, input.Plaintext, c, t, input.AssociatedData);
            });

            WithSecretKey(backend, session, CKK.CKK_CHACHA20, input.Key, b => b.Encrypt().Decrypt(), key =>
            {
                using var chacha = new ChaCha20Poly1305Pkcs11(key);
                AssertAeadMatches(input, ciphertext, tag, chacha.Encrypt, chacha.Decrypt);
            });
        });
    }

    private delegate void SealInto(byte[] ciphertext, byte[] tag);

    private delegate void AeadEncrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> associatedData);

    private delegate void AeadDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> associatedData);

    private static (byte[] Ciphertext, byte[] Tag) Seal(AeadCase input, SealInto seal)
    {
        byte[] ciphertext = new byte[input.Plaintext.Length];
        byte[] tag = new byte[input.TagSize];
        seal(ciphertext, tag);
        return (ciphertext, tag);
    }

    // The token seals to the BCL's ciphertext and tag, and opens the BCL's.
    private static void AssertAeadMatches(AeadCase input, byte[] ciphertext, byte[] tag, AeadEncrypt encrypt, AeadDecrypt decrypt)
    {
        byte[] tokenCiphertext = new byte[input.Plaintext.Length];
        byte[] tokenTag = new byte[input.TagSize];
        encrypt(input.Nonce, input.Plaintext, tokenCiphertext, tokenTag, input.AssociatedData);
        Assert.Equal(ciphertext, tokenCiphertext);
        Assert.Equal(tag, tokenTag);

        byte[] plaintext = new byte[ciphertext.Length];
        decrypt(input.Nonce, ciphertext, tag, plaintext, input.AssociatedData);
        Assert.Equal(input.Plaintext, plaintext);
    }

    // === KDFs ==============================================================================
    //
    // The byte-returning overloads read the derived value back, which the default policy refuses; these
    // properties opt in for their session. NSS refuses the read-back itself (its wrapper gates them on
    // NssBackendFixture.ExtractableDeriveAvailable).

    // HKDF extract, and extract-then-expand to any length up to 512 bytes, with any salt (empty included)
    // and info.
    internal static void Assert_Hkdf_MatchesBcl(IPkcs11Backend backend, string hashName)
    {
        backend.RequireMechanism(CKM.CKM_HKDF_DERIVE);
        HashSpec spec = Hash(hashName);
        RequireHost(spec.HostSupportsHmac(), $"Host BCL has no HMAC over {hashName}.");
        var hash = new HashAlgorithmName(hashName);

        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var inputs =
            from ikm in CsInputs.Bytes(1, 128)
            from salt in CsInputs.Bytes(0, 64)
            from info in CsInputs.Bytes(0, 64)
            from length in CsInputs.Int(1, Math.Min(255 * spec.Size, 512))
            select (ikm, salt, info, length);

        CsInputs.Check(inputs, input =>
            WithSecretKey(backend, session, CKK.CKK_GENERIC_SECRET, input.ikm, b => b.Derive(), ikm =>
            {
                Assert.Equal(HKDF.Extract(hash, input.ikm, input.salt), HkdfPkcs11.Extract(hash, ikm, input.salt));
                Assert.Equal(
                    HKDF.DeriveKey(hash, input.ikm, input.length, input.salt, input.info),
                    HkdfPkcs11.DeriveKey(hash, ikm, input.length, input.salt, input.info));
            }));
    }

    // SP 800-108 counter mode over HMAC, any label, context and output length up to 256 bytes.
    internal static void Assert_Sp800108HmacCounter_MatchesBcl(IPkcs11Backend backend, string hashName)
    {
        backend.RequireMechanism(CKM.CKM_SP800_108_COUNTER_KDF);
        var hash = new HashAlgorithmName(hashName);

        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var inputs =
            from key in CsInputs.Bytes(16, 64)
            from label in CsInputs.Bytes(0, 64)
            from context in CsInputs.Bytes(0, 64)
            from length in CsInputs.Int(1, 256)
            select (key, label, context, length);

        CsInputs.Check(inputs, input =>
            WithSecretKey(backend, session, CKK.CKK_GENERIC_SECRET, input.key, b => b.Derive().Sign(), key =>
            {
                using var kdf = new SP800108HmacCounterKdfPkcs11(key, hash);
                Assert.Equal(
                    SP800108HmacCounterKdf.DeriveBytes(input.key, hash, input.label, input.context, input.length),
                    kdf.DeriveKey(input.label, input.context, input.length));
            }));
    }

    // PBKDF2 with any password (empty included), a salt of 16 bytes or more, and an output that spans one
    // to several PRF blocks. The iteration count stays near SP 800-132's floor of 1000, which FreeHSM
    // enforces: the property is about the inputs' encoding, which a higher count only slows down.
    internal static void Assert_Pbkdf2_MatchesBcl(IPkcs11Backend backend, string hashName)
    {
        backend.RequireMechanism(CKM.CKM_PKCS5_PBKD2);
        var hash = new HashAlgorithmName(hashName);

        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var inputs =
            from password in CsInputs.Bytes(0, 64)
            from salt in CsInputs.Bytes(16, 64)
            from iterations in CsInputs.Int(1000, 1100)
            from length in CsInputs.Int(1, 160)
            select (password, salt, iterations, length);

        CsInputs.Check(inputs, input =>
            Assert.Equal(
                Rfc2898DeriveBytes.Pbkdf2(input.password, input.salt, input.iterations, hash, input.length),
                Rfc2898DeriveBytesPkcs11.Pbkdf2(session, input.password.AsSpan(), input.salt, input.iterations, hash, input.length)));
    }
}
