using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// AesPkcs11 over the in-process <c>ManagedSoftToken</c> (a BCL-backed PKCS#11 fake), mirroring the
/// SoftHSM behavior set without any native module. The token performs CBC / CBC-PAD / ECB / CFB via the BCL,
/// so the adapter's output is cross-checked against <see cref="Aes"/> for the same imported key — a true
/// known-answer assertion that a non-extractable SoftHSM key cannot give. CBC and ECB are unauthenticated
/// and gated by the secure-defaults policy: each throws <see cref="CryptoPolicyViolationException"/> outside
/// an <c>UsePolicy(CryptoPolicy.AllowInsecure)</c>. The managed-key / streaming surface is <see cref="NotSupportedException"/>.
/// (Backend sibling of <c>AesPkcs11Tests.SoftHsm2.cs</c>.)
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class AesPkcs11_Managed
{
    private static readonly byte[] Key256 =
        Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    private static readonly byte[] Iv16 =
        Convert.FromHexString("0F0E0D0C0B0A09080706050403020100");

    // Imports Key256 as a managed-token AES key and hands a wrapping AesPkcs11 (and its session)
    // to the body.
    private static void WithImportedAes(Action<Pkcs11Session, AesPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("aes").Value(Key256).Encrypt().Decrypt().Build();
        using var key = session.ImportKey(tpl);
        using var aes = new AesPkcs11(key);
        body(session, aes);
    }

    private static Aes BclAes()
    {
        var bcl = Aes.Create();
        bcl.Key = Key256;
        return bcl;
    }

    // === Construction and argument validation (run before any token call) =================

    [Fact]
    public void Ctor_NullKey_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new AesPkcs11(null!));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public void Ctor_NonAesKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("gen").ValueLen(32).Sign().Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new AesPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }

    // === CBC: gated, and the token's output must match the BCL once unlocked ==============

    [Fact]
    public void EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl() => WithImportedAes((session, aes) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("AES-CBC PKCS7 over a managed-token key — variable length.");

        // CBC (even with PKCS7) is unauthenticated and gated by the secure-defaults policy.
        Assert.Throws<CryptoPolicyViolationException>(() => aes.EncryptCbc(plaintext, Iv16));

        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            using var bcl = BclAes();
            byte[] ct = aes.EncryptCbc(plaintext, Iv16); // default PaddingMode.PKCS7
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv16), ct);
            Assert.Equal(plaintext, aes.DecryptCbc(ct, Iv16));
        }
    });

    [Fact]
    public void EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl() => WithImportedAes((session, aes) =>
    {
        byte[] plaintext = new byte[32]; // exactly two blocks
        RandomNumberGenerator.Fill(plaintext);

        Assert.Throws<CryptoPolicyViolationException>(() => aes.EncryptCbc(plaintext, Iv16, PaddingMode.None));

        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            using var bcl = BclAes();
            byte[] ct = aes.EncryptCbc(plaintext, Iv16, PaddingMode.None);
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv16, PaddingMode.None), ct);
            Assert.Equal(plaintext, aes.DecryptCbc(ct, Iv16, PaddingMode.None));
        }
    });

    // Reverse direction: a ciphertext produced by the BCL must decrypt on the token.
    // The managed token unpads CKM_*_CBC_PAD with the BCL, so it refuses what the BCL refuses; the shared
    // case pins the same paddings on every real backend.
    [Fact]
    public void DecryptCbc_InvalidPaddingOrPartialBlock_Throws_SessionReusable() => WithImportedAes((session, aes) =>
    {
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using var bcl = BclAes();
        CbcPaddingTestSupport.AssertRefusesBadPadding_SessionReusable(aes, bcl, Iv16);
    });

    [Fact]
    public void DecryptCbc_BclCiphertext_RoundTrips() => WithImportedAes((session, aes) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("BCL → token interop over CBC-PKCS7.");
        byte[] ct;
        using (var bcl = BclAes())
            ct = bcl.EncryptCbc(plaintext, Iv16);

        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            Assert.Equal(plaintext, aes.DecryptCbc(ct, Iv16));
    });

    [Fact]
    public void EncryptCbc_UnsupportedPadding_Throws() => WithImportedAes((ws, aes) =>
        Assert.Throws<NotSupportedException>(() => aes.EncryptCbc(new byte[16], Iv16, PaddingMode.Zeros)));

    [Fact]
    public void Cbc_EmptyInput_MatchesBcl() => WithImportedAes((session, aes) =>
    {
        // Even the empty-input fast path honors the secure-defaults gate: without the AllowInsecure policy the
        // gated mechanism throws before the (empty) buffer reaches the token.
        Assert.Throws<CryptoPolicyViolationException>(() => aes.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv16));

        // Under the AllowInsecure policy, unpadded empty input is a no-op; padded, it is refused as the BCL refuses it.
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            Assert.Empty(aes.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv16, PaddingMode.None));
            Assert.ThrowsAny<CryptographicException>(() => aes.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv16));
        }
    });

    // Refuses every encryption and allows everything else, so the two directions of one mechanism differ.
    private sealed class NoEncryptPolicy : ICryptoPolicy
    {
        public string Name => "NoEncrypt";
        public bool AllowsOverride => false;
        public PolicyDecision Evaluate(PolicyRequest request)
            => request is MechanismUseRequest { Operation: CryptoOperation.Encrypt } ? PolicyDecision.Deny("no encryption") : PolicyDecision.Allow;
    }

    // The empty-input shortcut asks the policy about the direction it is skipping, not the other one.
    [Fact]
    public void Cbc_EmptyInput_IsJudgedForItsOwnDirection()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library, new NoEncryptPolicy());
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label("aes").Value(Key256).Encrypt().Decrypt().Build();
        using var key = session.ImportKey(tpl);
        using var aes = new AesPkcs11(key);

        Assert.Throws<CryptoPolicyViolationException>(() => aes.EncryptCbc(ReadOnlySpan<byte>.Empty, Iv16, PaddingMode.None));
        Assert.Empty(aes.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv16, PaddingMode.None));
    }

    // The plaintext length is known only once the token has decrypted, so a short destination is reported
    // by the return value rather than refused up front.
    [Fact]
    public void TryDecryptCbc_DestinationTooSmall_ReturnsFalse() => WithImportedAes((session, aes) =>
    {
        using var bcl = BclAes();
        byte[] ciphertext = bcl.EncryptCbc(new byte[20], Iv16); // 32 bytes, 20 of plaintext

        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            Assert.False(aes.TryDecryptCbc(ciphertext, Iv16, new byte[16], out int written));
            Assert.Equal(0, written);
        }
    });

    // === Key wrap with padding (RFC 5649) ==================================================

    // Imports Key256 on a managed token that advertises CKM_AES_KEY_WRAP_KWP or not, with the given
    // C_GetMechanismInfo flags for it.
    private static void WithKwpToken(bool advertisesKwp, Action<ManagedSoftToken, Pkcs11Session, AesPkcs11> body, ulong? kwpFlags = null)
    {
        var token = new ManagedSoftToken { AdvertisesAesKeyWrapKwp = advertisesKwp };
        if (kwpFlags is { } flags)
            token.AesKeyWrapKwpFlags = flags;
        WithToken(token, body);
    }

    private static void WithToken(ManagedSoftToken token, Action<ManagedSoftToken, Pkcs11Session, AesPkcs11> body)
    {
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label("aes").Value(Key256).Encrypt().Decrypt().Build();
        using var key = session.ImportKey(tpl);
        using var aes = new AesPkcs11(key);
        body(token, session, aes);
    }

    // On a token with CKM_AES_KEY_WRAP_KWP the wrap is one operation there, allowed by the default
    // policy, and gives the BCL's RFC 5649 output, whatever the padding needed.
    [Theory]
    [InlineData(1)]
    [InlineData(8)]
    [InlineData(20)]
    [InlineData(32)]
    public void KeyWrapPadded_IsTheTokensKwp_UnderTheDefaultPolicy_AndMatchesBcl(int keyLength) => WithKwpToken(advertisesKwp: true, (token, _, aes) =>
    {
        byte[] keyToWrap = RandomNumberGenerator.GetBytes(keyLength);
        using var bcl = BclAes();
        int initsBefore = token.EncryptInitCallCount;

        byte[] wrapped = aes.EncryptKeyWrapPadded(keyToWrap);

        Assert.Equal(1, token.EncryptInitCallCount - initsBefore);
        Assert.Equal(bcl.EncryptKeyWrapPadded(keyToWrap), wrapped);
        Assert.Equal(keyToWrap, aes.DecryptKeyWrapPadded(wrapped));
        Assert.Equal(keyToWrap, aes.DecryptKeyWrapPadded(bcl.EncryptKeyWrapPadded(keyToWrap)));
    });

    // As in the BCL, a wrap that fails its integrity check throws CryptographicException.
    [Fact]
    public void DecryptKeyWrapPadded_Tampered_Throws() => WithKwpToken(advertisesKwp: true, (_, _, aes) =>
    {
        byte[] wrapped = aes.EncryptKeyWrapPadded(new byte[20]);
        wrapped[^1] ^= 0x01;

        var e = Assert.Throws<CryptographicException>(() => aes.DecryptKeyWrapPadded(wrapped));
        Assert.Equal(CKR.CKR_ENCRYPTED_DATA_INVALID, Assert.IsAssignableFrom<Pkcs11Exception>(e.InnerException).ReturnValue);
    });

    // A token without the mechanism keeps the base class's managed RFC 5649 over AES-ECB, which the
    // policy judges as ECB: refused by default, the same output once ECB is allowed.
    [Fact]
    public void KeyWrapPadded_WithoutKwp_FallsBackToEcb_JudgedAsEcb() => WithKwpToken(advertisesKwp: false, AssertFallsBackToEcb);

    // So does a token that lists CKM_AES_KEY_WRAP_KWP for C_WrapKey/C_UnwrapKey only, whose C_Encrypt and
    // C_Decrypt with it fail with CKR_MECHANISM_INVALID.
    [Fact]
    public void KeyWrapPadded_KwpForWrapAndUnwrapOnly_FallsBackToEcb_JudgedAsEcb() =>
        WithKwpToken(advertisesKwp: true, AssertFallsBackToEcb, kwpFlags: CKF.CKF_WRAP | CKF.CKF_UNWRAP);

    // Each direction checks its own flag: with CKF_ENCRYPT alone the wrap is the token's, under the default
    // policy, and the unwrap falls back to ECB.
    [Fact]
    public void KeyWrapPadded_KwpForEncryptOnly_WrapsOnTheToken_UnwrapFallsBackToEcb() =>
        WithKwpToken(advertisesKwp: true, (token, session, aes) =>
        {
            byte[] keyToWrap = RandomNumberGenerator.GetBytes(20);
            using var bcl = BclAes();
            int initsBefore = token.EncryptInitCallCount;

            byte[] wrapped = aes.EncryptKeyWrapPadded(keyToWrap);
            Assert.Equal(1, token.EncryptInitCallCount - initsBefore);
            Assert.Equal(bcl.EncryptKeyWrapPadded(keyToWrap), wrapped);

            var refused = Assert.Throws<CryptoPolicyViolationException>(() => aes.DecryptKeyWrapPadded(wrapped));
            Assert.Equal(CKM.CKM_AES_ECB, refused.Mechanism);
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                Assert.Equal(keyToWrap, aes.DecryptKeyWrapPadded(wrapped));
        }, kwpFlags: CKF.CKF_ENCRYPT | CKF.CKF_WRAP | CKF.CKF_UNWRAP);

    private static void AssertFallsBackToEcb(ManagedSoftToken _, Pkcs11Session session, AesPkcs11 aes)
    {
        byte[] keyToWrap = RandomNumberGenerator.GetBytes(20);
        using var bcl = BclAes();

        var refused = Assert.Throws<CryptoPolicyViolationException>(() => aes.EncryptKeyWrapPadded(keyToWrap));
        Assert.Equal(CKM.CKM_AES_ECB, refused.Mechanism);

        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            byte[] wrapped = aes.EncryptKeyWrapPadded(keyToWrap);
            Assert.Equal(bcl.EncryptKeyWrapPadded(keyToWrap), wrapped);
            Assert.Equal(keyToWrap, aes.DecryptKeyWrapPadded(wrapped));
        }
    }

    // === ECB: gated, and the token's output must match the BCL once unlocked ==============

    [Fact]
    public void EncryptEcb_GatedByDefault_Throws() => WithImportedAes((ws, aes) =>
        Assert.Throws<CryptoPolicyViolationException>(() => aes.EncryptEcb(new byte[16], PaddingMode.None)));

    [Fact]
    public void EncryptEcb_WithAllowInsecure_MatchesBcl() => WithImportedAes((session, aes) =>
    {
        byte[] plaintext = new byte[48]; // three blocks
        RandomNumberGenerator.Fill(plaintext);

        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            using var bcl = BclAes();
            byte[] ct = aes.EncryptEcb(plaintext, PaddingMode.None);
            Assert.Equal(bcl.EncryptEcb(plaintext, PaddingMode.None), ct);
            Assert.Equal(plaintext, aes.DecryptEcb(ct, PaddingMode.None));
        }
    });

    [Fact]
    public void EncryptEcb_UnsupportedPadding_Throws() => WithImportedAes((session, aes) =>
    {
        // The padding switch runs before the token call, so the gate is irrelevant here; assert the
        // NotSupportedException both inside and (by default) outside the insecure scope.
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            Assert.Throws<NotSupportedException>(() => aes.EncryptEcb(new byte[16], PaddingMode.PKCS7));
    });

    // === CFB: gated, and the token's output must match the BCL once unlocked ===================

    [Fact]
    public void Cfb_GatedByDefault_Throws() => WithImportedAes((ws, aes) =>
        Assert.Throws<CryptoPolicyViolationException>(
            () => aes.EncryptCfb(new byte[16], Iv16, PaddingMode.None, feedbackSizeInBits: 128)));

    [Fact]
    public void Cfb_WithAllowInsecure_GateBypassed() => WithImportedAes((session, aes) =>
    {
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            // The secure-defaults gate must NOT fire once the AllowInsecure policy is used.
            Exception? ex = Record.Exception(
                () => aes.EncryptCfb(new byte[16], Iv16, PaddingMode.None, feedbackSizeInBits: 128));
            Assert.False(ex is CryptoPolicyViolationException,
                $"Gate should be bypassed; got {ex?.GetType().Name ?? "no exception"}.");
        }
    });

    [Theory]
    [InlineData(8)]
    [InlineData(128)]
    public void Cfb_OneShots_MatchBclAtEveryLength(int feedbackSizeInBits) => WithImportedAes((session, aes) =>
    {
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            AesPkcs11TestCases.AssertCfbOneShotsMatchBcl(aes, feedbackSizeInBits, 0, 1, 15, 16, 17, 32);
    });

    // The managed token, like CKM_AES_CFB128 on a real one, accepts a partial final segment: the adapter
    // refuses it as the BCL does, before C_EncryptInit.
    [Fact]
    public void Cfb128_PartialSegment_ThrowsLikeBcl_BeforeTheToken() => WithKwpToken(advertisesKwp: true, (token, session, aes) =>
    {
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            int initsBefore = token.EncryptInitCallCount;
            AesPkcs11TestCases.AssertCfbOneShotsMatchBcl(aes, 128, 1, 15, 17, 31);
            Assert.Equal(initsBefore, token.EncryptInitCallCount);
            Assert.Throws<CryptographicException>(() => aes.DecryptCfb(new byte[17], Iv16, PaddingMode.None, 128));
        }
    });

    // A token that leaves a single-part CFB C_Encrypt's output length as the caller passed it, the buffer's
    // size (opencryptoki does), still gives the BCL's output: CFB's output is as long as its input.
    [Theory]
    [InlineData(8)]
    [InlineData(128)]
    public void Cfb_TokenReportsTheBufferSize_MatchesBcl(int feedbackSizeInBits) =>
        WithToken(new ManagedSoftToken { ReportedCfbLength = (buffer, _) => buffer }, (_, session, aes) =>
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                AesPkcs11TestCases.AssertCfbOneShotsMatchBcl(aes, feedbackSizeInBits, 0, 1, 15, 16, 17, 32);
        });

    // A token reporting less CFB output than input gave no CFB result.
    [Fact]
    public void Cfb_TokenReportsShortOutput_Throws() =>
        WithToken(new ManagedSoftToken { ReportedCfbLength = (_, output) => output - 1 }, (_, session, aes) =>
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            {
                byte[] destination = new byte[16];
                Assert.Throws<CryptographicException>(() => aes.TryEncryptCfb(new byte[16], Iv16, destination, out int written, PaddingMode.None, 128));
                Assert.Throws<CryptographicException>(() => aes.TryDecryptCfb(new byte[16], Iv16, destination, out int written, PaddingMode.None, 128));
            }
        });

    [Fact]
    public void Cfb_NonNonePadding_Throws() => WithImportedAes((ws, aes) =>
        Assert.Throws<NotSupportedException>(
            () => aes.EncryptCfb(new byte[16], Iv16, PaddingMode.PKCS7, feedbackSizeInBits: 128)));

    [Fact]
    public void Cfb_UnsupportedFeedbackSize_Throws() => WithImportedAes((ws, aes) =>
        Assert.Throws<NotSupportedException>(
            () => aes.EncryptCfb(new byte[16], Iv16, PaddingMode.None, feedbackSizeInBits: 64)));

    // === Key size: the token key's, which cannot be changed ================================

    // KeySize is the token key's CKA_VALUE_LEN, and LegalKeySizes that size alone, so setting another
    // size fails rather than changing what is reported for an unchanged key.
    [Theory]
    [InlineData(16, 128, 256)]
    [InlineData(32, 256, 128)]
    public void KeySize_IsTheTokenKeys_AndCannotBeChanged(int keyBytes, int bits, int otherBits)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label("aes").Value(new byte[keyBytes]).Encrypt().Decrypt().Build();
        using var key = session.ImportKey(tpl);
        using var aes = new AesPkcs11(key);

        Assert.Equal(bits, aes.KeySize);
        KeySizes legal = Assert.Single(aes.LegalKeySizes);
        Assert.Equal((bits, bits, 0), (legal.MinSize, legal.MaxSize, legal.SkipSize));

        Assert.Throws<CryptographicException>(() => aes.KeySize = otherBits);
        aes.KeySize = bits;
        Assert.Equal(bits, aes.KeySize);
    }

    // === IV generation ====================================================================

    [Fact]
    public void GenerateIV_ProducesBlockSizedIv() => WithImportedAes((ws, aes) =>
    {
        aes.GenerateIV();
        Assert.Equal(16, aes.IV.Length);
    });

    // === Generated-key round-trip (key never enters managed memory) =======================

    [Fact]
    public void GeneratedKey_CbcPkcs7_RoundTrips()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("aes-gen").ValueLen(32).Encrypt().Decrypt().Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl);
        using var aes = new AesPkcs11(key);

        byte[] plaintext = RandomNumberGenerator.GetBytes(40);
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            byte[] ct = aes.EncryptCbc(plaintext, Iv16);
            Assert.NotEqual(plaintext, ct);
            Assert.Equal(plaintext, aes.DecryptCbc(ct, Iv16));
        }
    }

    // === Managed-key / streaming surface is not supported =================================

    [Fact]
    public void ManagedKeyAndStreamingSurface_NotSupported() => WithImportedAes((ws, aes) =>
    {
        Assert.Throws<NotSupportedException>(() => aes.CreateEncryptor(new byte[32], new byte[16]));
        Assert.Throws<NotSupportedException>(() => aes.CreateDecryptor(new byte[32], new byte[16]));
        Assert.Throws<NotSupportedException>(() => aes.GenerateKey());
        Assert.Throws<NotSupportedException>(() => { _ = aes.Key; });
        Assert.Throws<NotSupportedException>(() => aes.Key = new byte[32]);
    });
}
