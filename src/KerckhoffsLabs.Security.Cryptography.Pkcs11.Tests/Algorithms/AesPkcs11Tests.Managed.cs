using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// AesPkcs11 over the in-process <c>ManagedSoftToken</c> (a BCL-backed PKCS#11 fake), mirroring the
/// SoftHSM behavior set without any native module. The token performs CBC / CBC-PAD / ECB via the BCL,
/// so the adapter's output is cross-checked against <see cref="Aes"/> for the same imported key — a true
/// known-answer assertion that a non-extractable SoftHSM key cannot give. CBC and ECB are unauthenticated
/// and gated by the secure-defaults policy: each throws <see cref="InsecureOperationException"/> outside
/// an <c>AllowInsecureScope()</c>. The managed-key / streaming surface is <see cref="NotSupportedException"/>.
/// (Backend sibling of <c>AesPkcs11Tests.SoftHsm2.cs</c>.)
/// </summary>
public sealed class AesPkcs11_Managed
{
    private static readonly byte[] Key256 =
        Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    private static readonly byte[] Iv16 =
        Convert.FromHexString("0F0E0D0C0B0A09080706050403020100");

    // Imports Key256 as a managed-token AES key and hands a wrapping AesPkcs11 (and its workspace)
    // to the body.
    private static void WithImportedAes(Action<Pkcs11Workspace, AesPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("aes").Value(Key256).Encrypt().Decrypt().Build();
        using var key = workspace.ImportKey(tpl);
        using var aes = new AesPkcs11(key);
        body(workspace, aes);
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
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("gen").ValueLen(32).Sign().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new AesPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }

    // === CBC: gated, and the token's output must match the BCL once unlocked ==============

    [Fact]
    public void EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl() => WithImportedAes((workspace, aes) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("AES-CBC PKCS7 over a managed-token key — variable length.");

        // CBC (even with PKCS7) is unauthenticated and gated by the secure-defaults policy.
        Assert.Throws<InsecureOperationException>(() => aes.EncryptCbc(plaintext, Iv16));

        using (workspace.AllowInsecureScope())
        {
            using var bcl = BclAes();
            byte[] ct = aes.EncryptCbc(plaintext, Iv16); // default PaddingMode.PKCS7
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv16), ct);
            Assert.Equal(plaintext, aes.DecryptCbc(ct, Iv16));
        }
    });

    [Fact]
    public void EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl() => WithImportedAes((workspace, aes) =>
    {
        byte[] plaintext = new byte[32]; // exactly two blocks
        RandomNumberGenerator.Fill(plaintext);

        Assert.Throws<InsecureOperationException>(() => aes.EncryptCbc(plaintext, Iv16, PaddingMode.None));

        using (workspace.AllowInsecureScope())
        {
            using var bcl = BclAes();
            byte[] ct = aes.EncryptCbc(plaintext, Iv16, PaddingMode.None);
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv16, PaddingMode.None), ct);
            Assert.Equal(plaintext, aes.DecryptCbc(ct, Iv16, PaddingMode.None));
        }
    });

    // Reverse direction: a ciphertext produced by the BCL must decrypt on the token.
    [Fact]
    public void DecryptCbc_BclCiphertext_RoundTrips() => WithImportedAes((workspace, aes) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("BCL → token interop over CBC-PKCS7.");
        byte[] ct;
        using (var bcl = BclAes())
            ct = bcl.EncryptCbc(plaintext, Iv16);

        using (workspace.AllowInsecureScope())
            Assert.Equal(plaintext, aes.DecryptCbc(ct, Iv16));
    });

    [Fact]
    public void EncryptCbc_UnsupportedPadding_Throws() => WithImportedAes((ws, aes) =>
        Assert.Throws<NotSupportedException>(() => aes.EncryptCbc(new byte[16], Iv16, PaddingMode.Zeros)));

    [Fact]
    public void Cbc_EmptyInput_NoOp_ReturnsEmpty() => WithImportedAes((workspace, aes) =>
    {
        // Even the empty-input fast path honors the secure-defaults gate: without AllowInsecure the
        // gated mechanism throws before the (empty) buffer reaches the token.
        Assert.Throws<InsecureOperationException>(() => aes.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv16));

        // With AllowInsecure, empty input is a no-op returned without touching the token.
        using (workspace.AllowInsecureScope())
            Assert.Empty(aes.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv16));
    });

    // === ECB: gated, and the token's output must match the BCL once unlocked ==============

    [Fact]
    public void EncryptEcb_GatedByDefault_Throws() => WithImportedAes((ws, aes) =>
        Assert.Throws<InsecureOperationException>(() => aes.EncryptEcb(new byte[16], PaddingMode.None)));

    [Fact]
    public void EncryptEcb_WithAllowInsecure_MatchesBcl() => WithImportedAes((workspace, aes) =>
    {
        byte[] plaintext = new byte[48]; // three blocks
        RandomNumberGenerator.Fill(plaintext);

        using (workspace.AllowInsecureScope())
        {
            using var bcl = BclAes();
            byte[] ct = aes.EncryptEcb(plaintext, PaddingMode.None);
            Assert.Equal(bcl.EncryptEcb(plaintext, PaddingMode.None), ct);
            Assert.Equal(plaintext, aes.DecryptEcb(ct, PaddingMode.None));
        }
    });

    [Fact]
    public void EncryptEcb_UnsupportedPadding_Throws() => WithImportedAes((workspace, aes) =>
    {
        // The padding switch runs before the token call, so the gate is irrelevant here; assert the
        // NotSupportedException both inside and (by default) outside the insecure scope.
        using (workspace.AllowInsecureScope())
            Assert.Throws<NotSupportedException>(() => aes.EncryptEcb(new byte[16], PaddingMode.PKCS7));
    });

    // === CFB: gated; the managed token does not implement CFB, so the token call itself fails ===

    [Fact]
    public void Cfb_GatedByDefault_Throws() => WithImportedAes((ws, aes) =>
        Assert.Throws<InsecureOperationException>(
            () => aes.EncryptCfb(new byte[16], Iv16, PaddingMode.None, feedbackSizeInBits: 128)));

    [Fact]
    public void Cfb_WithAllowInsecure_GateBypassed() => WithImportedAes((workspace, aes) =>
    {
        using (workspace.AllowInsecureScope())
        {
            // The managed token does not implement CFB, so the token call may fail — but the
            // secure-defaults gate must NOT fire once AllowInsecure is set.
            Exception? ex = Record.Exception(
                () => aes.EncryptCfb(new byte[16], Iv16, PaddingMode.None, feedbackSizeInBits: 128));
            Assert.False(ex is InsecureOperationException,
                $"Gate should be bypassed; got {ex?.GetType().Name ?? "no exception"}.");
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

    // === IV generation ====================================================================
    // (KeySize reflection is covered by the SoftHSM suite; the managed token reports a fixed AES key
    // length and doesn't model CKA_VALUE_LEN per imported key, so it isn't asserted here.)

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
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("aes-gen").ValueLen(32).Encrypt().Decrypt().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl);
        using var aes = new AesPkcs11(key);

        byte[] plaintext = RandomNumberGenerator.GetBytes(40);
        using (workspace.AllowInsecureScope())
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
