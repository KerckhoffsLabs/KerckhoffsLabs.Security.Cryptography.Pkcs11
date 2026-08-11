using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// RC2Pkcs11 is [Obsolete] (weak legacy 64-bit cipher with a reduced effective key length); the
// secure-defaults gate is the whole point of the type, so KLPKCS11005 is suppressed deliberately at the
// use sites.
#pragma warning disable KLPKCS11005

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// RC2Pkcs11 over the in-process <c>ManagedSoftToken</c> (a BCL-backed PKCS#11 fake). Unlike SoftHSM —
/// which implements no RC2 at all, forcing its KATs to skip — the managed token genuinely implements
/// <c>CKM_RC2_CBC/CBC_PAD/ECB</c> on top of the BCL <see cref="RC2"/> (honouring the RFC 2268
/// effective-key-bits mechanism parameter), so every known-answer round-trip runs here and is
/// cross-checked against the BCL primitive for the same key, IV and effective key size.
/// <para>
/// RC2 is gated on two fronts. The secure-defaults policy means each cipher op must run inside
/// <c>AllowInsecureScope()</c> and throws <see cref="InsecureOperationException"/> without it. The BCL
/// <see cref="RC2"/> implementation is Windows-only (it throws <c>PlatformNotSupportedException</c>
/// elsewhere), so the crypto cases are gated on <see cref="Rc2Supported"/>; the construction and
/// argument-validation cases that throw before any token call stay <c>[Fact]</c>.
/// </para>
/// </summary>
public sealed class RC2Pkcs11Tests_Managed
{
    // The BCL RC2 is Windows-only; gate every case that reaches the token (encrypt/decrypt) on this.
    public static bool Rc2Supported => OperatingSystem.IsWindows();

    private static readonly byte[] Key128 = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
    private static readonly byte[] Iv8 = Convert.FromHexString("1020304050607080");
    private const int EffectiveBits = 128;

    private static byte[] H(string hex) => Convert.FromHexString(hex);

    // Imports Key128 as a token RC2 key and hands a wrapping RC2Pkcs11 (and its workspace) to the body.
    private static void WithImportedRc2(Action<Pkcs11Workspace, RC2Pkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_RC2)
            .Label($"rc2-{Guid.NewGuid():N}").Value(Key128).Encrypt().Decrypt().Build();
        using var key = workspace.ImportKey(tpl);
        using var rc2 = new RC2Pkcs11(key) { EffectiveKeySize = EffectiveBits };
        body(workspace, rc2);
    }

    private static RC2 BclRc2()
    {
        var bcl = RC2.Create();
        bcl.Key = Key128;
        bcl.EffectiveKeySize = EffectiveBits;
        return bcl;
    }

    // === Construction / argument surface (throws before any token call) =============================

    [Fact]
    public void Ctor_NullKey_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new RC2Pkcs11(null!));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public void Ctor_NonRc2Key_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("gen").ValueLen(32).Sign().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new RC2Pkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }

    // The ctor reflects the token key's CKA_VALUE_LEN into KeySize (and thus the EffectiveKeySize
    // default) when it is a legal RC2 size; a 16-byte key → 128 bits.
    [Fact]
    public void Ctor_ReflectsTokenKeySize()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_RC2)
            .Label($"rc2-{Guid.NewGuid():N}").Value(Key128).Encrypt().Decrypt().Build();
        using var key = workspace.ImportKey(tpl);
        using var rc2 = new RC2Pkcs11(key);
        Assert.Equal(128, rc2.KeySize);
    }

    // === Secure-defaults gate (fires before any token call — no Windows RC2 needed) =================

    [Fact]
    public void EncryptCbc_Pkcs7_GatedByDefault_Throws() => WithImportedRc2((ws, rc2) =>
        Assert.Throws<InsecureOperationException>(() => rc2.EncryptCbc(new byte[8], Iv8)));

    [Fact]
    public void EncryptCbc_NonePadding_GatedByDefault_Throws() => WithImportedRc2((ws, rc2) =>
        Assert.Throws<InsecureOperationException>(() => rc2.EncryptCbc(new byte[8], Iv8, PaddingMode.None)));

    [Fact]
    public void DecryptCbc_GatedByDefault_Throws() => WithImportedRc2((ws, rc2) =>
        Assert.Throws<InsecureOperationException>(() => rc2.DecryptCbc(new byte[8], Iv8)));

    [Fact]
    public void EncryptEcb_GatedByDefault_Throws() => WithImportedRc2((ws, rc2) =>
        Assert.Throws<InsecureOperationException>(() => rc2.EncryptEcb(new byte[8], PaddingMode.None)));

    // === Known-answer round-trips vs the BCL (the managed token implements RC2 on Windows) ==========

    [ConditionalFact(nameof(Rc2Supported))]
    public void EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl() => WithImportedRc2((workspace, rc2) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("RC2-CBC PKCS7 over a token key — variable length.");

        using var bcl = BclRc2();
        byte[] expected = bcl.EncryptCbc(plaintext, Iv8); // default PaddingMode.PKCS7
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = rc2.EncryptCbc(plaintext, Iv8);
            Assert.Equal(expected, ct);
            Assert.Equal(plaintext, rc2.DecryptCbc(ct, Iv8));
        }
    });

    [ConditionalFact(nameof(Rc2Supported))]
    public void EncryptCbc_NonePadding_AllowInsecure_MatchesBcl() => WithImportedRc2((workspace, rc2) =>
    {
        byte[] plaintext = new byte[16]; // exactly two 8-byte blocks
        RandomNumberGenerator.Fill(plaintext);

        using var bcl = BclRc2();
        byte[] expected = bcl.EncryptCbc(plaintext, Iv8, PaddingMode.None);
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = rc2.EncryptCbc(plaintext, Iv8, PaddingMode.None);
            Assert.Equal(expected, ct);
            Assert.Equal(plaintext, rc2.DecryptCbc(ct, Iv8, PaddingMode.None));
        }
    });

    [ConditionalFact(nameof(Rc2Supported))]
    public void EncryptEcb_AllowInsecure_MatchesBcl() => WithImportedRc2((workspace, rc2) =>
    {
        byte[] plaintext = new byte[8];
        RandomNumberGenerator.Fill(plaintext);

        using var bcl = BclRc2();
        byte[] expected = bcl.EncryptEcb(plaintext, PaddingMode.None);
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = rc2.EncryptEcb(plaintext, PaddingMode.None);
            Assert.Equal(expected, ct);
            Assert.Equal(plaintext, rc2.DecryptEcb(ct, PaddingMode.None));
        }
    });

    // (The RFC 2268 effective-key-bits KAT and the effective>key rejection are exercised by the
    // SoftHsm suite over OpenSSL RC2; the managed token's BCL RC2 is Windows-only and Windows CNG
    // applies a different default EffectiveKeySize, so those sub-128-bit-key cases aren't run here.)

    // Reverse direction: ciphertext produced by the BCL must decrypt on the token.
    [ConditionalFact(nameof(Rc2Supported))]
    public void DecryptCbc_BclCiphertext_RoundTrips() => WithImportedRc2((workspace, rc2) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("token decrypts BCL RC2 ciphertext");
        using var bcl = BclRc2();
        byte[] ct = bcl.EncryptCbc(plaintext, Iv8);

        using (workspace.AllowInsecureScope())
            Assert.Equal(plaintext, rc2.DecryptCbc(ct, Iv8));
    });

    // A wrong IV corrupts the leading block under CBC (no integrity, so it does not throw).
    [ConditionalFact(nameof(Rc2Supported))]
    public void DecryptCbc_WrongIv_ProducesDifferentPlaintext() => WithImportedRc2((workspace, rc2) =>
    {
        byte[] plaintext = new byte[16];
        RandomNumberGenerator.Fill(plaintext);
        using var bcl = BclRc2();
        byte[] ct = bcl.EncryptCbc(plaintext, Iv8, PaddingMode.None);

        byte[] wrongIv = Iv8.ToArray();
        wrongIv[0] ^= 0xFF;
        using (workspace.AllowInsecureScope())
        {
            byte[] dec = rc2.DecryptCbc(ct, wrongIv, PaddingMode.None);
            Assert.NotEqual(plaintext, dec);
        }
    });

    // === Empty-input handling (gate first, then no-op fast path) ====================================

    [Fact]
    public void Cbc_EmptyInput_Gated_Throws() => WithImportedRc2((ws, rc2) =>
        // Even the empty-input fast path honours the secure-defaults gate: without AllowInsecure the
        // gated mechanism throws before the (empty) buffer reaches the token.
        Assert.Throws<InsecureOperationException>(() => rc2.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8)));

    [ConditionalFact(nameof(Rc2Supported))]
    public void DecryptCbc_EmptyInput_AllowInsecure_NoOp_ReturnsEmpty() => WithImportedRc2((workspace, rc2) =>
    {
        // With AllowInsecure, empty decrypt is a no-op returned without touching the token.
        using (workspace.AllowInsecureScope())
            Assert.Empty(rc2.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8));
    });

    [ConditionalFact(nameof(Rc2Supported))]
    public void EncryptCbc_Pkcs7_EmptyInput_AllowInsecure_EmitsPaddingBlock() => WithImportedRc2((workspace, rc2) =>
    {
        // Empty plaintext with PKCS7 must still emit a full 8-byte padding block; that path goes to the
        // token rather than the empty-input fast path. Cross-check against the BCL.
        using var bcl = BclRc2();
        byte[] expected = bcl.EncryptCbc(ReadOnlySpan<byte>.Empty, Iv8);
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = rc2.EncryptCbc(ReadOnlySpan<byte>.Empty, Iv8);
            Assert.Equal(8, ct.Length);
            Assert.Equal(expected, ct);
            Assert.Empty(rc2.DecryptCbc(ct, Iv8));
        }
    });


    // === NotSupported / argument surface (no token call) ===========================================

    [Fact]
    public void EncryptCbc_UnsupportedPadding_Throws() => WithImportedRc2((ws, rc2) =>
        Assert.Throws<NotSupportedException>(() => rc2.EncryptCbc(new byte[8], Iv8, PaddingMode.Zeros)));

    [Fact]
    public void EncryptEcb_UnsupportedPadding_Throws() => WithImportedRc2((ws, rc2) =>
        Assert.Throws<NotSupportedException>(() => rc2.EncryptEcb(new byte[8], PaddingMode.PKCS7)));

    [Fact]
    public void GenerateIV_ProducesBlockSizedIv() => WithImportedRc2((ws, rc2) =>
    {
        rc2.GenerateIV();
        Assert.Equal(8, rc2.IV.Length);
    });

    [Fact]
    public void ManagedKeyAndStreamingSurface_NotSupported() => WithImportedRc2((ws, rc2) =>
    {
        Assert.Throws<NotSupportedException>(() => rc2.CreateEncryptor(new byte[16], new byte[8]));
        Assert.Throws<NotSupportedException>(() => rc2.CreateDecryptor(new byte[16], new byte[8]));
        Assert.Throws<NotSupportedException>(() => rc2.GenerateKey());
        Assert.Throws<NotSupportedException>(() => { _ = rc2.Key; });
        Assert.Throws<NotSupportedException>(() => rc2.Key = new byte[16]);
    });
}
