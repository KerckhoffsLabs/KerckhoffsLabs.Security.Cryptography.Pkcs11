using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// DESPkcs11 is [Obsolete] (single DES has a 56-bit key); the secure-defaults gate is the whole point
// of the type, so KLPKCS11003 is suppressed deliberately at the use sites.
#pragma warning disable KLPKCS11003

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// DESPkcs11 over the in-process <c>ManagedSoftToken</c> (a BCL-backed PKCS#11 fake). Unlike a
/// FIPS-built SoftHSM — which advertises but refuses single DES, forcing the SoftHsm KATs to skip —
/// the managed token genuinely implements <c>CKM_DES_CBC/CBC_PAD/ECB</c> on top of the BCL
/// <see cref="DES"/>, so every known-answer round-trip runs here and is cross-checked against the BCL.
/// The secure-defaults gate is still in force: each cipher op must run inside
/// <c>AllowInsecureScope()</c> and throws <see cref="InsecureOperationException"/> without it.
/// </summary>
public sealed class DESPkcs11Tests_Managed
{
    // Classic NBS DES test key (0x0123456789ABCDEF) — not weak/semi-weak, so the BCL DES key setter
    // accepts it for the known-answer comparison.
    private static readonly byte[] Key64 = Convert.FromHexString("0123456789ABCDEF");
    private static readonly byte[] Iv8 = Convert.FromHexString("1020304050607080");

    private static byte[] H(string hex) => Convert.FromHexString(hex);

    // Imports Key64 as a token DES key and hands a wrapping DESPkcs11 (and its workspace) to the body.
    private static void WithImportedDes(Action<Pkcs11Workspace, DESPkcs11> body) =>
        WithImportedDes(Key64, body);

    private static void WithImportedDes(byte[] keyBytes, Action<Pkcs11Workspace, DESPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_DES)
            .Label($"des-{Guid.NewGuid():N}").Value(keyBytes).Encrypt().Decrypt().Build();
        using var key = workspace.ImportKey(tpl);
        using var des = new DESPkcs11(key);
        body(workspace, des);
    }

    private static DES BclDes()
    {
        var bcl = DES.Create();
        bcl.Key = Key64;
        return bcl;
    }

    // === Construction / argument surface (throws before any token call) =============================

    [Fact]
    public void Ctor_NullKey_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new DESPkcs11(null!));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public void Ctor_NonDesKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("gen").ValueLen(32).Sign().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new DESPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }

    // === Secure-defaults gate (fires before any token call — no DES support needed) =================

    [Fact]
    public void EncryptCbc_Pkcs7_GatedByDefault_Throws() => WithImportedDes((ws, des) =>
        Assert.Throws<InsecureOperationException>(() => des.EncryptCbc(new byte[8], Iv8)));

    [Fact]
    public void EncryptCbc_NonePadding_GatedByDefault_Throws() => WithImportedDes((ws, des) =>
        Assert.Throws<InsecureOperationException>(() => des.EncryptCbc(new byte[8], Iv8, PaddingMode.None)));

    [Fact]
    public void EncryptEcb_GatedByDefault_Throws() => WithImportedDes((ws, des) =>
        Assert.Throws<InsecureOperationException>(() => des.EncryptEcb(new byte[8], PaddingMode.None)));

    [Fact]
    public void DecryptCbc_GatedByDefault_Throws() => WithImportedDes((ws, des) =>
        Assert.Throws<InsecureOperationException>(() => des.DecryptCbc(new byte[8], Iv8)));

    // === Known-answer round-trips vs the BCL (the managed token implements single DES) ==============

    [Fact]
    public void EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl() => WithImportedDes((workspace, des) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("DES-CBC PKCS7 over a token key — variable length.");

        using var bcl = BclDes();
        byte[] expected = bcl.EncryptCbc(plaintext, Iv8); // default PaddingMode.PKCS7
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = des.EncryptCbc(plaintext, Iv8);
            Assert.Equal(expected, ct);
            Assert.Equal(plaintext, des.DecryptCbc(ct, Iv8));
        }
    });

    [Fact]
    public void EncryptCbc_NonePadding_AllowInsecure_MatchesBcl() => WithImportedDes((workspace, des) =>
    {
        byte[] plaintext = new byte[16]; // exactly two 8-byte blocks
        RandomNumberGenerator.Fill(plaintext);

        using var bcl = BclDes();
        byte[] expected = bcl.EncryptCbc(plaintext, Iv8, PaddingMode.None);
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = des.EncryptCbc(plaintext, Iv8, PaddingMode.None);
            Assert.Equal(expected, ct);
            Assert.Equal(plaintext, des.DecryptCbc(ct, Iv8, PaddingMode.None));
        }
    });

    [Fact]
    public void EncryptEcb_AllowInsecure_MatchesBcl() => WithImportedDes((workspace, des) =>
    {
        byte[] plaintext = new byte[8];
        RandomNumberGenerator.Fill(plaintext);

        using var bcl = BclDes();
        byte[] expected = bcl.EncryptEcb(plaintext, PaddingMode.None);
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = des.EncryptEcb(plaintext, PaddingMode.None);
            Assert.Equal(expected, ct);
            Assert.Equal(plaintext, des.DecryptEcb(ct, PaddingMode.None));
        }
    });

    // Fixed known-answer vector: NBS single-DES, ECB, key 0x0123456789ABCDEF,
    // plaintext 0x4E6F772069732074 ("Now is t") → ciphertext 0x3FA40E8A984D4815.
    [Fact]
    public void EncryptEcb_KnownAnswer_MatchesReferenceVector() => WithImportedDes((workspace, des) =>
    {
        byte[] plaintext = H("4E6F772069732074");
        byte[] expectedCt = H("3FA40E8A984D4815");

        using (workspace.AllowInsecureScope())
        {
            byte[] ct = des.EncryptEcb(plaintext, PaddingMode.None);
            Assert.Equal(expectedCt, ct);
            Assert.Equal(plaintext, des.DecryptEcb(expectedCt, PaddingMode.None));
        }

        // Independent confirmation that the vector matches the BCL primitive as well.
        using var bcl = BclDes();
        Assert.Equal(expectedCt, bcl.EncryptEcb(plaintext, PaddingMode.None));
    });

    // Reverse direction: ciphertext produced by the BCL must decrypt on the token.
    [Fact]
    public void DecryptCbc_BclCiphertext_RoundTrips() => WithImportedDes((workspace, des) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("token decrypts BCL ciphertext");
        using var bcl = BclDes();
        byte[] ct = bcl.EncryptCbc(plaintext, Iv8);

        using (workspace.AllowInsecureScope())
            Assert.Equal(plaintext, des.DecryptCbc(ct, Iv8));
    });

    // A wrong IV corrupts the leading block under CBC (no integrity, so it does not throw).
    [Fact]
    public void DecryptCbc_WrongIv_ProducesDifferentPlaintext() => WithImportedDes((workspace, des) =>
    {
        byte[] plaintext = new byte[16];
        RandomNumberGenerator.Fill(plaintext);
        using var bcl = BclDes();
        byte[] ct = bcl.EncryptCbc(plaintext, Iv8, PaddingMode.None);

        byte[] wrongIv = (byte[])Iv8.Clone();
        wrongIv[0] ^= 0xFF;
        using (workspace.AllowInsecureScope())
        {
            byte[] dec = des.DecryptCbc(ct, wrongIv, PaddingMode.None);
            Assert.NotEqual(plaintext, dec);
        }
    });

    // === Empty-input handling (gate first, then no-op fast path) ====================================

    [Fact]
    public void Cbc_EmptyInput_Gated_Throws() => WithImportedDes((ws, des) =>
        // Even the empty-input fast path honors the secure-defaults gate: without AllowInsecure the
        // gated mechanism throws before the (empty) buffer reaches the token.
        Assert.Throws<InsecureOperationException>(() => des.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8)));

    [Fact]
    public void DecryptCbc_EmptyInput_AllowInsecure_NoOp_ReturnsEmpty() => WithImportedDes((workspace, des) =>
    {
        // With AllowInsecure, empty decrypt is a no-op returned without touching the token.
        using (workspace.AllowInsecureScope())
            Assert.Empty(des.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8));
    });

    [Fact]
    public void EncryptCbc_Pkcs7_EmptyInput_AllowInsecure_EmitsPaddingBlock() => WithImportedDes((workspace, des) =>
    {
        // Empty plaintext with PKCS7 must still emit a full 8-byte padding block; that path goes to the
        // token rather than the empty-input fast path. Cross-check against the BCL.
        using var bcl = BclDes();
        byte[] expected = bcl.EncryptCbc(ReadOnlySpan<byte>.Empty, Iv8);
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = des.EncryptCbc(ReadOnlySpan<byte>.Empty, Iv8);
            Assert.Equal(8, ct.Length);
            Assert.Equal(expected, ct);
            Assert.Empty(des.DecryptCbc(ct, Iv8));
        }
    });

    // === NotSupported / argument surface (no token call) ===========================================

    [Fact]
    public void EncryptCbc_UnsupportedPadding_Throws() => WithImportedDes((ws, des) =>
        Assert.Throws<NotSupportedException>(() => des.EncryptCbc(new byte[8], Iv8, PaddingMode.Zeros)));

    [Fact]
    public void EncryptEcb_UnsupportedPadding_Throws() => WithImportedDes((ws, des) =>
        Assert.Throws<NotSupportedException>(() => des.EncryptEcb(new byte[8], PaddingMode.PKCS7)));

    [Fact]
    public void Cfb_NotSupported() => WithImportedDes((workspace, des) =>
    {
        // DESPkcs11 does not override the CFB cores: the secure-defaults gate in Pkcs11Session does
        // not cover single-DES CKM_DES_CFB*, so wiring it would bypass AllowInsecure. The base
        // SymmetricAlgorithm therefore surfaces NotSupportedException — even with AllowInsecure set.
        using (workspace.AllowInsecureScope())
            Assert.Throws<NotSupportedException>(
                () => des.EncryptCfb(new byte[8], Iv8, PaddingMode.None, feedbackSizeInBits: 8));
    });

    [Fact]
    public void GenerateIV_ProducesBlockSizedIv() => WithImportedDes((ws, des) =>
    {
        des.GenerateIV();
        Assert.Equal(8, des.IV.Length);
    });

    [Fact]
    public void ManagedKeyAndStreamingSurface_NotSupported() => WithImportedDes((ws, des) =>
    {
        Assert.Throws<NotSupportedException>(() => des.CreateEncryptor(new byte[8], new byte[8]));
        Assert.Throws<NotSupportedException>(() => des.CreateDecryptor(new byte[8], new byte[8]));
        Assert.Throws<NotSupportedException>(() => des.GenerateKey());
        Assert.Throws<NotSupportedException>(() => { _ = des.Key; });
        Assert.Throws<NotSupportedException>(() => des.Key = new byte[8]);
    });
}
