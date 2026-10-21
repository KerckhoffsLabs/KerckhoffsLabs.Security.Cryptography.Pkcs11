using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic AesPkcs11 tests: token AES-CBC/ECB must match the BCL for the same imported key,
/// CBC/ECB/CFB are gated by the secure-defaults policy (require the AllowInsecure policy), and the managed-key /
/// streaming surface is NotSupported. Cases that perform a real cipher op skip where the backend does
/// not advertise the mechanism; the gate and NotSupported cases run on any backend (they fire in
/// managed code before the token).
/// </summary>
internal static class AesPkcs11TestCases
{
    private static readonly byte[] Key256 =
        Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    private static readonly byte[] Iv16 =
        Convert.FromHexString("0F0E0D0C0B0A09080706050403020100");

    // A fresh IV for each encryption on the token. Every test imports the same Key256, and Craton HSM
    // refuses an IV it has already seen under the same key value, across sessions and objects, so
    // encrypting with Key256 and the fixed Iv16 would pass or fail depending on test order. Iv16 stays
    // for calls that never encrypt on the token.
    private static byte[] NewIv() => RandomNumberGenerator.GetBytes(16);

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

    // Imports Key256 as a token AES key and hands a wrapping AesPkcs11 (and its session) to the body.
    private static void WithImportedAes(IPkcs11Backend backend, Action<Pkcs11Session, AesPkcs11> body)
    {
        using var session = OpenSession(backend);
        string label = $"aes-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(Key256).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = session.ImportKey(tpl);
            using var aes = new AesPkcs11(key);
            body(session, aes);
        }
        finally { DestroyByLabel(session, label); }
    }

    private static Aes BclAes()
    {
        var bcl = Aes.Create();
        bcl.Key = Key256;
        return bcl;
    }

    internal static void Assert_Ctor_NonAesKey_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN);
        using var session = OpenSession(backend);
        string label = $"nonaes-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(32).Sign().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t);
        }
        try
        {
            using var key = session.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new AesPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(session, label); }
    }

    internal static void Assert_EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl(IPkcs11Backend backend) =>
        WithImportedAes(backend, (session, aes) =>
        {
            backend.RequireMechanism(CKM.CKM_AES_CBC);
            byte[] plaintext = Encoding.UTF8.GetBytes("AES-CBC PKCS7 over a token key — variable length.");

            // CBC (even with PKCS7) is unauthenticated and gated by the secure-defaults policy.
            Assert.Throws<CryptoPolicyViolationException>(() => aes.EncryptCbc(plaintext, Iv16));

            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            using var bcl = BclAes();
            byte[] iv = NewIv();
            byte[] ct = aes.EncryptCbc(plaintext, iv); // default PaddingMode.PKCS7
            Assert.Equal(bcl.EncryptCbc(plaintext, iv), ct);
            Assert.Equal(plaintext, aes.DecryptCbc(ct, iv));
        });

    internal static void Assert_EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl(IPkcs11Backend backend) =>
        WithImportedAes(backend, (session, aes) =>
        {
            backend.RequireMechanism(CKM.CKM_AES_CBC);
            byte[] plaintext = new byte[32]; // exactly two blocks
            RandomNumberGenerator.Fill(plaintext);

            Assert.Throws<CryptoPolicyViolationException>(() => aes.EncryptCbc(plaintext, Iv16, PaddingMode.None));

            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            using var bcl = BclAes();
            byte[] iv = NewIv();
            byte[] ct = aes.EncryptCbc(plaintext, iv, PaddingMode.None);
            Assert.Equal(bcl.EncryptCbc(plaintext, iv, PaddingMode.None), ct);
            Assert.Equal(plaintext, aes.DecryptCbc(ct, iv, PaddingMode.None));
        });

    internal static void Assert_Cfb_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithImportedAes(backend, (_, aes) =>
            Assert.Throws<CryptoPolicyViolationException>(
                () => aes.EncryptCfb(new byte[16], Iv16, PaddingMode.None, feedbackSizeInBits: 128)));

    internal static void Assert_Cfb_WithAllowInsecure_GateBypassed(IPkcs11Backend backend) =>
        WithImportedAes(backend, (session, aes) =>
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            // The token may not implement CFB, so the call may fail — but the secure-defaults gate must
            // NOT fire once the AllowInsecure policy is used.
            Exception? ex = Record.Exception(
                () => aes.EncryptCfb(new byte[16], Iv16, PaddingMode.None, feedbackSizeInBits: 128));
            Assert.False(ex is CryptoPolicyViolationException,
                $"Gate should be bypassed; got {ex?.GetType().Name ?? "no exception"}.");
        });

    internal static void Assert_Cfb_NonNonePadding_Throws(IPkcs11Backend backend) =>
        WithImportedAes(backend, (_, aes) =>
            Assert.Throws<NotSupportedException>(
                () => aes.EncryptCfb(new byte[16], Iv16, PaddingMode.PKCS7, feedbackSizeInBits: 128)));

    // The eight CFB one-shots without padding, each returning what it wrote. Four of them (the Try pair and
    // the destination pair) and both array DecryptCfb overloads leave the length check to the Core.
    private static readonly (string Name, Func<SymmetricAlgorithm, byte[], int, byte[]> Run)[] CfbOneShots =
    [
        ("EncryptCfb(byte[])", (alg, input, bits) => alg.EncryptCfb(input, Iv16, PaddingMode.None, bits)),
        ("EncryptCfb(ReadOnlySpan)", (alg, input, bits) => alg.EncryptCfb((ReadOnlySpan<byte>)input, Iv16, PaddingMode.None, bits)),
        ("EncryptCfb(destination)", (alg, input, bits) =>
        {
            byte[] destination = new byte[input.Length];
            return destination[..alg.EncryptCfb(input, Iv16, destination, PaddingMode.None, bits)];
        }),
        ("TryEncryptCfb", (alg, input, bits) =>
        {
            byte[] destination = new byte[input.Length];
            Assert.True(alg.TryEncryptCfb(input, Iv16, destination, out int written, PaddingMode.None, bits));
            return destination[..written];
        }),
        ("DecryptCfb(byte[])", (alg, input, bits) => alg.DecryptCfb(input, Iv16, PaddingMode.None, bits)),
        ("DecryptCfb(ReadOnlySpan)", (alg, input, bits) => alg.DecryptCfb((ReadOnlySpan<byte>)input, Iv16, PaddingMode.None, bits)),
        ("DecryptCfb(destination)", (alg, input, bits) =>
        {
            byte[] destination = new byte[input.Length];
            return destination[..alg.DecryptCfb(input, Iv16, destination, PaddingMode.None, bits)];
        }),
        ("TryDecryptCfb", (alg, input, bits) =>
        {
            byte[] destination = new byte[input.Length];
            Assert.True(alg.TryDecryptCfb(input, Iv16, destination, out int written, PaddingMode.None, bits));
            return destination[..written];
        }),
    ];

    // The output in hex, or what a one-shot refuses its input with: an ArgumentException from the base's
    // checks, or a CryptographicException (Pkcs11Exception among them) from the Core or the token. Anything
    // else is a failure of the case itself, and propagates.
    private static string CfbOutcome(Func<byte[]> run)
    {
        try { return Convert.ToHexString(run()); }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            return $"{ex.GetType().Name} (ParamName {(ex as ArgumentException)?.ParamName})";
        }
    }

    // Runs every CFB one-shot on the adapter and on the BCL for each input length and asserts the same
    // output, or the same exception type and ParamName. The caller permits CFB under the session's policy.
    internal static void AssertCfbOneShotsMatchBcl(AesPkcs11 aes, int feedbackSizeInBits, params int[] lengths)
    {
        using var bcl = BclAes();
        string[] mismatches =
        [
            .. from length in lengths
               let input = Enumerable.Range(1, length).Select(i => (byte)i).ToArray()
               from oneShot in CfbOneShots
               let expected = CfbOutcome(() => oneShot.Run(bcl, input, feedbackSizeInBits))
               let actual = CfbOutcome(() => oneShot.Run(aes, input, feedbackSizeInBits))
               where expected != actual
               select $"{oneShot.Name}, CFB{feedbackSizeInBits}, {length} bytes: BCL {expected}, AesPkcs11 {actual}",
        ];
        Assert.True(mismatches.Length == 0, string.Join("\n", mismatches));
    }

    internal static void Assert_Cfb_OneShots_MatchBclAtEveryLength(IPkcs11Backend backend, int feedbackSizeInBits)
    {
        backend.RequireMechanisms(feedbackSizeInBits == 8 ? CKM.CKM_AES_CFB8 : CKM.CKM_AES_CFB128);
        WithImportedAes(backend, (session, aes) =>
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            AssertCfbOneShotsMatchBcl(aes, feedbackSizeInBits, 0, 1, 15, 16, 17, 32);
        });
    }

    // Unpadded CFB128 input that is not a whole number of 16-byte segments is refused before the token, so
    // this runs on a token without CFB too.
    internal static void Assert_Cfb128_PartialSegment_ThrowsLikeBcl(IPkcs11Backend backend) =>
        WithImportedAes(backend, (session, aes) =>
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            AssertCfbOneShotsMatchBcl(aes, 128, 1, 15, 17, 31);
        });

    internal static void Assert_EncryptCbc_UnsupportedPadding_Throws(IPkcs11Backend backend) =>
        WithImportedAes(backend, (_, aes) =>
            Assert.Throws<NotSupportedException>(() => aes.EncryptCbc(new byte[16], Iv16, PaddingMode.Zeros)));

    internal static void Assert_EncryptEcb_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithImportedAes(backend, (_, aes) =>
            Assert.Throws<CryptoPolicyViolationException>(() => aes.EncryptEcb(new byte[16], PaddingMode.None)));

    internal static void Assert_EncryptEcb_WithAllowInsecure_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedAes(backend, (session, aes) =>
        {
            backend.RequireMechanism(CKM.CKM_AES_ECB);
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            byte[] plaintext = new byte[16];
            RandomNumberGenerator.Fill(plaintext);
            using var bcl = BclAes();

            byte[] ct = aes.EncryptEcb(plaintext, PaddingMode.None);
            Assert.Equal(bcl.EncryptEcb(plaintext, PaddingMode.None), ct);
            Assert.Equal(plaintext, aes.DecryptEcb(ct, PaddingMode.None));
        });

    // A token that advertises CKM_AES_KEY_WRAP_KWP wraps in one operation, under the default policy, and
    // gives the BCL's RFC 5649 output; each side unwraps the other's.
    internal static void Assert_KeyWrapPadded_UsesTheTokensKwp_AndMatchesBcl(IPkcs11Backend backend) =>
        WithImportedAes(backend, (_, aes) =>
        {
            backend.RequireMechanismFlags(CKM.CKM_AES_KEY_WRAP_KWP, f => f.Encrypt && f.Decrypt, "CKF_ENCRYPT and CKF_DECRYPT");
            byte[] keyToWrap = RandomNumberGenerator.GetBytes(20);
            using var bcl = BclAes();

            byte[] wrapped = aes.EncryptKeyWrapPadded(keyToWrap);

            Assert.Equal(bcl.EncryptKeyWrapPadded(keyToWrap), wrapped);
            Assert.Equal(keyToWrap, aes.DecryptKeyWrapPadded(wrapped));
            Assert.Equal(keyToWrap, bcl.DecryptKeyWrapPadded(wrapped));
        });

    internal static void Assert_GenerateIV_ProducesBlockSizedIv(IPkcs11Backend backend) =>
        WithImportedAes(backend, (_, aes) =>
        {
            aes.GenerateIV();
            Assert.Equal(16, aes.IV.Length);
        });

    internal static void Assert_KeySize_ReflectsTokenKeyLength(IPkcs11Backend backend, int keyBytes, int expectedBits)
    {
        using var session = OpenSession(backend);
        string label = $"aes-ks-{Guid.NewGuid():N}";
        byte[] raw = new byte[keyBytes];
        RandomNumberGenerator.Fill(raw);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(raw).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = session.ImportKey(tpl);
            using var aes = new AesPkcs11(key);
            Assert.Equal(expectedBits, aes.KeySize);
        }
        finally { DestroyByLabel(session, label); }
    }

    // Empty CBC input follows the BCL: unpadded it is a no-op, and padded decryption is refused, since a padded
    // ciphertext holds at least one block (returning empty would accept a ciphertext with no padding at all).
    internal static void Assert_Cbc_EmptyInput_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedAes(backend, (session, aes) =>
        {
            // The empty-input fast path still honors the gate: without the AllowInsecure policy the gated mechanism
            // throws before the (empty) buffer reaches the token.
            Assert.Throws<CryptoPolicyViolationException>(() => aes.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv16));

            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            using var bcl = BclAes();
            Assert.ThrowsAny<CryptographicException>(() => bcl.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv16));
            Assert.ThrowsAny<CryptographicException>(() => aes.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv16));
            Assert.Empty(aes.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv16, PaddingMode.None));
        });

    // A ciphertext whose padding is wrong, or that is not a whole number of blocks, is refused with a
    // CryptographicException as in the BCL, and the session still decrypts afterwards. NSS hardened exactly this
    // check (Bug 2029448, Bug 1591315); SoftHSM2 ends the operation on it since a8d6c5f; openCryptoki refuses
    // it since d5beecc9 and f14f7a91.
    internal static void Assert_DecryptCbc_InvalidPaddingOrPartialBlock_Throws_SessionReusable(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_CBC, CKM.CKM_AES_CBC_PAD);
        WithImportedAes(backend, (session, aes) =>
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            using var bcl = BclAes();
            CbcPaddingTestSupport.AssertRefusesBadPadding_SessionReusable(aes, bcl, Iv16);
        });
    }

    internal static void Assert_ManagedKeyAndStreamingSurface_NotSupported(IPkcs11Backend backend) =>
        WithImportedAes(backend, (_, aes) =>
        {
            Assert.Throws<NotSupportedException>(() => aes.CreateEncryptor(new byte[32], new byte[16]));
            Assert.Throws<NotSupportedException>(() => aes.CreateDecryptor(new byte[32], new byte[16]));
            Assert.Throws<NotSupportedException>(() => aes.GenerateKey());
            Assert.Throws<NotSupportedException>(() => aes.Key);
        });
}
