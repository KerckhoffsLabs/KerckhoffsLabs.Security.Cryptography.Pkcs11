using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// TripleDESPkcs11 is [Obsolete] (64-bit block / Sweet32, NIST-deprecated); the secure-defaults gate is
// the whole point of the type, so KLPKCS11004 is suppressed deliberately at the use sites.
#pragma warning disable KLPKCS11004

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// TripleDESPkcs11 over the in-process <c>ManagedSoftToken</c> (a BCL-backed PKCS#11 fake). Unlike a
/// FIPS-built SoftHSM, the managed token genuinely implements <c>CKM_DES3_CBC/CBC_PAD/ECB</c> on top of
/// the BCL <see cref="TripleDES"/>, so every known-answer round-trip runs here and is cross-checked
/// against the BCL. The managed-key/streaming surface is NotSupported, CFB is NotSupported, and the
/// secure-defaults gate is still in force: each cipher op must run inside <c>AllowInsecureScope()</c> and
/// throws <see cref="InsecureOperationException"/> without it.
/// </summary>
public sealed class TripleDESPkcs11Tests_Managed
{
    // 24-byte three-key 3DES key with three distinct, non-weak DES subkeys, so the BCL TripleDES key
    // setter accepts it (it rejects keys that degenerate to single/double DES) for the KAT comparison.
    private static readonly byte[] Key192 =
        Convert.FromHexString("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123");

    // 16-byte two-key (2TDEA) 3DES key: K1 || K2, distinct non-weak subkeys. PKCS#11 models this as
    // CKK_DES2 (not CKK_DES3 with a short value) — TripleDESPkcs11 accepts either key type.
    private static readonly byte[] Key128 =
        Convert.FromHexString("0123456789ABCDEF23456789ABCDEF01");

    private static readonly byte[] Iv8 = Convert.FromHexString("1020304050607080");

    private static byte[] H(string hex) => Convert.FromHexString(hex);

    // Imports Key192 as a token 3DES key and hands a wrapping TripleDESPkcs11 (and its workspace) to the body.
    private static void WithImportedDes3(Action<Pkcs11Workspace, TripleDESPkcs11> body) =>
        WithImportedDes3(CKK.CKK_DES3, Key192, body);

    // Imports Key128 as a CKK_DES2 (two-key) token key and hands a wrapping TripleDESPkcs11 to the body.
    private static void WithImportedDes2(Action<Pkcs11Workspace, TripleDESPkcs11> body) =>
        WithImportedDes3(CKK.CKK_DES2, Key128, body);

    private static void WithImportedDes3(CKK keyType, byte[] keyBytes, Action<Pkcs11Workspace, TripleDESPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(keyType)
            .Label($"des3-{Guid.NewGuid():N}").Value(keyBytes).Encrypt().Decrypt().Build();
        using var key = workspace.ImportKey(tpl);
        using var des3 = new TripleDESPkcs11(key);
        body(workspace, des3);
    }

    private static TripleDES BclDes3()
    {
        var bcl = TripleDES.Create();
        bcl.Key = Key192;
        return bcl;
    }

    // === Construction / argument surface (throws before any token call) =============================

    [Fact]
    public void Ctor_NullKey_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new TripleDESPkcs11(null!));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public void Ctor_NonDes3Key_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("gen").ValueLen(32).Sign().Build();
        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new TripleDESPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public void KeySize_ReflectsTokenKeyLength() => WithImportedDes3((ws, des3) =>
        Assert.Equal(192, des3.KeySize));

    // === Secure-defaults gate (fires before any token call) =========================================

    [Fact]
    public void EncryptCbc_Pkcs7_GatedByDefault_Throws() => WithImportedDes3((ws, des3) =>
        Assert.Throws<InsecureOperationException>(() => des3.EncryptCbc(new byte[8], Iv8)));

    [Fact]
    public void EncryptCbc_NonePadding_GatedByDefault_Throws() => WithImportedDes3((ws, des3) =>
        Assert.Throws<InsecureOperationException>(() => des3.EncryptCbc(new byte[8], Iv8, PaddingMode.None)));

    [Fact]
    public void EncryptEcb_GatedByDefault_Throws() => WithImportedDes3((ws, des3) =>
        Assert.Throws<InsecureOperationException>(() => des3.EncryptEcb(new byte[8], PaddingMode.None)));

    [Fact]
    public void DecryptCbc_GatedByDefault_Throws() => WithImportedDes3((ws, des3) =>
        Assert.Throws<InsecureOperationException>(() => des3.DecryptCbc(new byte[8], Iv8)));

    // === Known-answer round-trips vs the BCL (the managed token implements 3DES) =====================

    [Fact]
    public void EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl() => WithImportedDes3((workspace, des3) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("3DES-CBC PKCS7 over a token key — variable length.");

        using var bcl = BclDes3();
        byte[] expected = bcl.EncryptCbc(plaintext, Iv8); // default PaddingMode.PKCS7
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = des3.EncryptCbc(plaintext, Iv8);
            Assert.Equal(expected, ct);
            Assert.Equal(plaintext, des3.DecryptCbc(ct, Iv8));
        }
    });

    [Fact]
    public void EncryptCbc_NonePadding_AllowInsecure_MatchesBcl() => WithImportedDes3((workspace, des3) =>
    {
        byte[] plaintext = new byte[16]; // exactly two 8-byte blocks
        RandomNumberGenerator.Fill(plaintext);

        using var bcl = BclDes3();
        byte[] expected = bcl.EncryptCbc(plaintext, Iv8, PaddingMode.None);
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = des3.EncryptCbc(plaintext, Iv8, PaddingMode.None);
            Assert.Equal(expected, ct);
            Assert.Equal(plaintext, des3.DecryptCbc(ct, Iv8, PaddingMode.None));
        }
    });

    [Fact]
    public void EncryptEcb_AllowInsecure_MatchesBcl() => WithImportedDes3((workspace, des3) =>
    {
        byte[] plaintext = new byte[8];
        RandomNumberGenerator.Fill(plaintext);

        using var bcl = BclDes3();
        byte[] expected = bcl.EncryptEcb(plaintext, PaddingMode.None);
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = des3.EncryptEcb(plaintext, PaddingMode.None);
            Assert.Equal(expected, ct);
            Assert.Equal(plaintext, des3.DecryptEcb(ct, PaddingMode.None));
        }
    });

    // Fixed known-answer vector: three-key 3DES (EDE), ECB, key Key192, plaintext 0x4E6F772069732074
    // ("Now is t"). The expected ciphertext is computed once by the BCL primitive and pinned here so the
    // token path is checked against a literal rather than only against a live BCL call.
    [Fact]
    public void EncryptEcb_KnownAnswer_MatchesReferenceVector() => WithImportedDes3((workspace, des3) =>
    {
        byte[] plaintext = H("4E6F772069732074");
        byte[] expectedCt = H("314F8327FA7A09A8");

        using (workspace.AllowInsecureScope())
        {
            byte[] ct = des3.EncryptEcb(plaintext, PaddingMode.None);
            Assert.Equal(expectedCt, ct);
            Assert.Equal(plaintext, des3.DecryptEcb(expectedCt, PaddingMode.None));
        }

        // Independent confirmation that the vector matches the BCL primitive as well.
        using var bcl = BclDes3();
        Assert.Equal(expectedCt, bcl.EncryptEcb(plaintext, PaddingMode.None));
    });

    // Reverse direction: ciphertext produced by the BCL must decrypt on the token.
    [Fact]
    public void DecryptCbc_BclCiphertext_RoundTrips() => WithImportedDes3((workspace, des3) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("token decrypts BCL 3DES ciphertext");
        using var bcl = BclDes3();
        byte[] ct = bcl.EncryptCbc(plaintext, Iv8);

        using (workspace.AllowInsecureScope())
            Assert.Equal(plaintext, des3.DecryptCbc(ct, Iv8));
    });

    // A wrong IV corrupts the leading block under CBC (no integrity, so it does not throw).
    [Fact]
    public void DecryptCbc_WrongIv_ProducesDifferentPlaintext() => WithImportedDes3((workspace, des3) =>
    {
        byte[] plaintext = new byte[16];
        RandomNumberGenerator.Fill(plaintext);
        using var bcl = BclDes3();
        byte[] ct = bcl.EncryptCbc(plaintext, Iv8, PaddingMode.None);

        byte[] wrongIv = (byte[])Iv8.Clone();
        wrongIv[0] ^= 0xFF;
        using (workspace.AllowInsecureScope())
        {
            byte[] dec = des3.DecryptCbc(ct, wrongIv, PaddingMode.None);
            Assert.NotEqual(plaintext, dec);
        }
    });

    // === Empty-input handling (gate first, then no-op fast path) ====================================

    [Fact]
    public void Cbc_EmptyInput_Gated_Throws() => WithImportedDes3((ws, des3) =>
        // Even the empty-input fast path honors the secure-defaults gate: without AllowInsecure the
        // gated mechanism throws before the (empty) buffer reaches the token.
        Assert.Throws<InsecureOperationException>(() => des3.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8)));

    [Fact]
    public void DecryptCbc_EmptyInput_AllowInsecure_NoOp_ReturnsEmpty() => WithImportedDes3((workspace, des3) =>
    {
        // With AllowInsecure, empty decrypt is a no-op returned without touching the token (so it does
        // not trip the token's empty-buffer rejection on CKM_DES3_CBC / CKM_DES3_CBC_PAD).
        using (workspace.AllowInsecureScope())
            Assert.Empty(des3.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8));
    });

    [Fact]
    public void EncryptCbc_Pkcs7_EmptyInput_AllowInsecure_EmitsPaddingBlock() => WithImportedDes3((workspace, des3) =>
    {
        // Empty plaintext with PKCS7 must still emit a full 8-byte padding block; that path goes to the
        // token rather than the empty-input fast path. Cross-check against the BCL.
        using var bcl = BclDes3();
        byte[] expected = bcl.EncryptCbc(ReadOnlySpan<byte>.Empty, Iv8);
        using (workspace.AllowInsecureScope())
        {
            byte[] ct = des3.EncryptCbc(ReadOnlySpan<byte>.Empty, Iv8);
            Assert.Equal(8, ct.Length);
            Assert.Equal(expected, ct);
            Assert.Empty(des3.DecryptCbc(ct, Iv8));
        }
    });

    // === NotSupported / argument surface (no token call) ===========================================

    [Fact]
    public void EncryptCbc_UnsupportedPadding_Throws() => WithImportedDes3((ws, des3) =>
        Assert.Throws<NotSupportedException>(() => des3.EncryptCbc(new byte[8], Iv8, PaddingMode.Zeros)));

    [Fact]
    public void EncryptEcb_UnsupportedPadding_Throws() => WithImportedDes3((ws, des3) =>
        Assert.Throws<NotSupportedException>(() => des3.EncryptEcb(new byte[8], PaddingMode.PKCS7)));

    [Fact]
    public void Cfb_NotSupported() => WithImportedDes3((workspace, des3) =>
    {
        // TripleDESPkcs11 does not override the CFB cores: PKCS#11 defines no CKM_DES3_CFB mechanism,
        // so the base SymmetricAlgorithm surfaces NotSupportedException — even with AllowInsecure set.
        using (workspace.AllowInsecureScope())
            Assert.Throws<NotSupportedException>(
                () => des3.EncryptCfb(new byte[8], Iv8, PaddingMode.None, feedbackSizeInBits: 8));
    });

    [Fact]
    public void GenerateIV_ProducesBlockSizedIv() => WithImportedDes3((ws, des3) =>
    {
        des3.GenerateIV();
        Assert.Equal(8, des3.IV.Length);
    });

    [Fact]
    public void ManagedKeyAndStreamingSurface_NotSupported() => WithImportedDes3((ws, des3) =>
    {
        Assert.Throws<NotSupportedException>(() => des3.CreateEncryptor(new byte[24], new byte[8]));
        Assert.Throws<NotSupportedException>(() => des3.CreateDecryptor(new byte[24], new byte[8]));
        Assert.Throws<NotSupportedException>(() => des3.GenerateKey());
        Assert.Throws<NotSupportedException>(() => { _ = des3.Key; });
        Assert.Throws<NotSupportedException>(() => des3.Key = new byte[24]);
    });

    // === Two-key (CKK_DES2, 128-bit) 3DES ==============================================
    // No KeySize test here: TripleDESPkcs11.KeySize reads CKA_VALUE_LEN, which a spec-correct token
    // rejects on C_CreateObject (import) and never derives afterward from CKA_VALUE alone — confirmed
    // against real SoftHSM2 (CKR_ATTRIBUTE_TYPE_INVALID when supplied, unreadable when omitted). The
    // 24-byte case's KeySize test only ever passed by coincidence: 192 is also TripleDES's base-class
    // default.

    // Fixed known-answer vector: two-key (2TDEA) 3DES-CBC, key Key128, plaintext "Now is t" + 8 zero
    // bytes (two 8-byte blocks, no padding). The BCL's own TripleDES cannot be used as the oracle here —
    // on OpenSSL-backed .NET, encrypting with a 16-byte (2-key) TripleDES key throws at operation time
    // ("invalid key length"), even though setting .Key succeeds — so the expected ciphertext is pinned,
    // computed independently (Python's `cryptography` library, which expands K1||K2 to K1||K2||K1 the
    // same way PKCS#11 tokens do).
    [Fact]
    public void TwoKeyDes3_EncryptCbc_KnownAnswer_MatchesReferenceVector() => WithImportedDes2((workspace, des3) =>
    {
        byte[] plaintext = H("4E6F7720697320740000000000000000");
        byte[] expectedCt = H("8DC1D44886D99D3004C55BEE813BEC9F");

        using (workspace.AllowInsecureScope())
        {
            byte[] ct = des3.EncryptCbc(plaintext, Iv8, PaddingMode.None);
            Assert.Equal(expectedCt, ct);
            Assert.Equal(plaintext, des3.DecryptCbc(expectedCt, Iv8, PaddingMode.None));
        }
    });
}
