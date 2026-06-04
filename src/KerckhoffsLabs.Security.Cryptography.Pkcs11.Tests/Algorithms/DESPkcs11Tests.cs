using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// DESPkcs11 is [Obsolete] (single DES has a 56-bit key); the secure-defaults gate is the point of
// the type, so CS0618 is suppressed deliberately at the use sites.
#pragma warning disable CS0618

/// <summary>Backend-free argument tests for <see cref="DESPkcs11"/>.</summary>
public sealed class DESPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new DESPkcs11(key: null!));
}

/// <summary>
/// DESPkcs11 over SoftHSM. Every test that only exercises the secure-defaults gate, the argument
/// surface, or the NotSupported surface runs unconditionally (the gate / NotSupported throws fire
/// before any token call). The known-answer tests additionally need the token to actually implement
/// single DES (<c>CKM_DES_CBC/ECB</c>) — a FIPS-built SoftHSM disables it (<c>#ifndef WITH_FIPS</c>),
/// so those skip via <see cref="SkipTestException"/> when the mechanism is absent.
/// </summary>
[Collection("SoftHsm")]
public sealed class DESPkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    // Classic NBS DES test key (0x0123456789ABCDEF) — not weak/semi-weak, so the BCL DES key setter
    // accepts it for the known-answer comparison.
    private static readonly byte[] Key64 = Convert.FromHexString("0123456789ABCDEF");
    private static readonly byte[] Iv8 = Convert.FromHexString("1020304050607080");

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

    // Imports Key64 as a token DES key and hands a wrapping DESPkcs11 (and its workspace) to the body.
    private void WithImportedDes(Action<Pkcs11Workspace, DESPkcs11> body)
    {
        using var workspace = OpenWorkspace();
        string label = $"des-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_DES)
            .Label(label).Value(Key64).Encrypt().Decrypt().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var des = new DESPkcs11(key);
            body(workspace, des);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // Single DES is optional: a FIPS-built SoftHSM compiles the CKM_DES_* operation paths out
    // (#ifndef WITH_FIPS) yet still ADVERTISES them in C_GetMechanismList — so the mechanism list
    // cannot be trusted to gate these KATs. Probe the real operation instead and translate the
    // token's "I don't actually implement this" signal (CKR_MECHANISM_INVALID from C_EncryptInit /
    // C_DecryptInit) into a skip. On a token that genuinely implements single DES the KAT runs in
    // full; only MECHANISM_INVALID is swallowed, so real failures still surface.
    private static byte[] OrSkipIfTokenLacksDes(Func<byte[]> tokenOp)
    {
        try
        {
            return tokenOp();
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_MECHANISM_INVALID)
        {
            throw new SkipTestException(
                "Token advertises single DES but its operation path rejects CKM_DES_* (FIPS-built SoftHSM); " +
                "cannot run the known-answer round-trip here.");
        }
    }

    private static DES BclDes()
    {
        var bcl = DES.Create();
        bcl.Key = Key64;
        return bcl;
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonDesKey_Throws()
    {
        using var workspace = OpenWorkspace();
        string label = $"nondes-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(32).Sign().OnToken().Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new DESPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Secure-defaults gate (runs regardless of token DES support — the gate fires first) =========

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_Pkcs7_GatedByDefault_Throws() => WithImportedDes((_, des) =>
        Assert.Throws<InsecureOperationException>(() => des.EncryptCbc(new byte[8], Iv8)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_NonePadding_GatedByDefault_Throws() => WithImportedDes((_, des) =>
        Assert.Throws<InsecureOperationException>(() => des.EncryptCbc(new byte[8], Iv8, PaddingMode.None)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptEcb_GatedByDefault_Throws() => WithImportedDes((_, des) =>
        Assert.Throws<InsecureOperationException>(() => des.EncryptEcb(new byte[8], PaddingMode.None)));

    // === Known-answer round-trips vs the BCL (require token single-DES support) =====================

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl() => WithImportedDes((workspace, des) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("DES-CBC PKCS7 over a token key — variable length.");

        workspace.AllowInsecure = true;
        using var bcl = BclDes();
        byte[] ct = OrSkipIfTokenLacksDes(() => des.EncryptCbc(plaintext, Iv8)); // default PaddingMode.PKCS7
        Assert.Equal(bcl.EncryptCbc(plaintext, Iv8), ct);
        Assert.Equal(plaintext, des.DecryptCbc(ct, Iv8));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_NonePadding_AllowInsecure_MatchesBcl() => WithImportedDes((workspace, des) =>
    {
        byte[] plaintext = new byte[16]; // exactly two 8-byte blocks
        RandomNumberGenerator.Fill(plaintext);

        workspace.AllowInsecure = true;
        using var bcl = BclDes();
        byte[] ct = OrSkipIfTokenLacksDes(() => des.EncryptCbc(plaintext, Iv8, PaddingMode.None));
        Assert.Equal(bcl.EncryptCbc(plaintext, Iv8, PaddingMode.None), ct);
        Assert.Equal(plaintext, des.DecryptCbc(ct, Iv8, PaddingMode.None));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptEcb_AllowInsecure_MatchesBcl() => WithImportedDes((workspace, des) =>
    {
        workspace.AllowInsecure = true;
        byte[] plaintext = new byte[8];
        RandomNumberGenerator.Fill(plaintext);
        using var bcl = BclDes();

        byte[] ct = OrSkipIfTokenLacksDes(() => des.EncryptEcb(plaintext, PaddingMode.None));
        Assert.Equal(bcl.EncryptEcb(plaintext, PaddingMode.None), ct);
        Assert.Equal(plaintext, des.DecryptEcb(ct, PaddingMode.None));
    });

    // === NotSupported / argument surface (no token call) ===========================================

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_UnsupportedPadding_Throws() => WithImportedDes((_, des) =>
        Assert.Throws<NotSupportedException>(() => des.EncryptCbc(new byte[8], Iv8, PaddingMode.Zeros)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Cfb_NotSupported() => WithImportedDes((workspace, des) =>
    {
        // DESPkcs11 does not override the CFB cores: the secure-defaults gate in Pkcs11Session does
        // not cover single-DES CKM_DES_CFB*, so wiring it would bypass AllowInsecure. The base
        // SymmetricAlgorithm therefore surfaces NotSupportedException — even with AllowInsecure set.
        workspace.AllowInsecure = true;
        Assert.Throws<NotSupportedException>(
            () => des.EncryptCfb(new byte[8], Iv8, PaddingMode.None, feedbackSizeInBits: 8));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateIV_ProducesBlockSizedIv() => WithImportedDes((_, des) =>
    {
        des.GenerateIV();
        Assert.Equal(8, des.IV.Length);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Cbc_EmptyInput_NoOp_ReturnsEmpty() => WithImportedDes((workspace, des) =>
    {
        // Even the empty-input fast path honors the secure-defaults gate: without AllowInsecure the
        // gated mechanism throws before the (empty) buffer reaches the token. The gate fires ahead of
        // any token call, so this needs no single-DES support.
        Assert.Throws<InsecureOperationException>(() => des.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8));

        // With AllowInsecure, empty input is a no-op returned without touching the token (so it
        // neither trips SoftHSM's empty-buffer rejection nor needs single-DES support).
        workspace.AllowInsecure = true;
        Assert.Empty(des.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => WithImportedDes((ws, des) =>
    {
        Assert.Throws<NotSupportedException>(() => des.CreateEncryptor(new byte[8], new byte[8]));
        Assert.Throws<NotSupportedException>(() => des.CreateDecryptor(new byte[8], new byte[8]));
        Assert.Throws<NotSupportedException>(() => des.GenerateKey());
        Assert.Throws<NotSupportedException>(() => { _ = des.Key; });
    });
}
