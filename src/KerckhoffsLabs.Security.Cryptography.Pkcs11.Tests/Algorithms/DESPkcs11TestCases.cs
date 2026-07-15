using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// DESPkcs11 is [Obsolete] (single DES has a 56-bit key); the secure-defaults gate is the point of the
// type, so KLPKCS11003 is suppressed deliberately at the use sites.
#pragma warning disable KLPKCS11003

/// <summary>
/// Backend-agnostic DESPkcs11 tests. The gate / argument / NotSupported cases run on any backend (they
/// throw before any token call). The known-answer round-trips additionally need the token to actually
/// implement single DES (<c>CKM_DES_CBC/ECB</c>); a FIPS build advertises but rejects it, so those skip
/// on <c>CKR_MECHANISM_INVALID</c>.
/// </summary>
internal static class DESPkcs11TestCases
{
    // Classic NBS DES test key (0x0123456789ABCDEF) — not weak/semi-weak, so the BCL key setter accepts it.
    private static readonly byte[] Key64 = Convert.FromHexString("0123456789ABCDEF");
    private static readonly byte[] Iv8 = Convert.FromHexString("1020304050607080");

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

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
    // Skips when the backend does not even advertise single DES.
    private static void WithImportedDes(IPkcs11Backend backend, Action<Pkcs11Workspace, DESPkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_DES_CBC))
            throw new SkipTestException("Backend does not advertise CKM_DES_CBC.");

        using var workspace = OpenWorkspace(backend);
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

    // Single DES is optional: a FIPS-built token compiles the CKM_DES_* operation paths out yet still
    // ADVERTISES them, so the mechanism list cannot gate the KATs. Probe the real operation and turn the
    // token's "I don't implement this" signal (CKR_MECHANISM_INVALID) into a skip; real failures surface.
    private static byte[] OrSkipIfTokenLacksDes(Func<byte[]> tokenOp)
    {
        try
        {
            return tokenOp();
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_MECHANISM_INVALID)
        {
            throw new SkipTestException(
                "Token advertises single DES but its operation path rejects CKM_DES_* (FIPS build).");
        }
    }

    private static DES BclDes()
    {
        var bcl = DES.Create();
        bcl.Key = Key64;
        return bcl;
    }

    internal static void Assert_Ctor_NonDesKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
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

    // === Secure-defaults gate (fires before any token call) =========================================

    internal static void Assert_EncryptCbc_Pkcs7_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithImportedDes(backend, (_, des) =>
            Assert.Throws<InsecureOperationException>(() => des.EncryptCbc(new byte[8], Iv8)));

    internal static void Assert_EncryptCbc_NonePadding_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithImportedDes(backend, (_, des) =>
            Assert.Throws<InsecureOperationException>(() => des.EncryptCbc(new byte[8], Iv8, PaddingMode.None)));

    internal static void Assert_EncryptEcb_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithImportedDes(backend, (_, des) =>
            Assert.Throws<InsecureOperationException>(() => des.EncryptEcb(new byte[8], PaddingMode.None)));

    // === Known-answer round-trips vs the BCL (require token single-DES support) =====================

    internal static void Assert_EncryptCbc_Pkcs7_AllowInsecure_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedDes(backend, (workspace, des) =>
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("DES-CBC PKCS7 over a token key — variable length.");

            workspace.AllowInsecure = true;
            using var bcl = BclDes();
            byte[] ct = OrSkipIfTokenLacksDes(() => des.EncryptCbc(plaintext, Iv8)); // default PaddingMode.PKCS7
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv8), ct);
            Assert.Equal(plaintext, des.DecryptCbc(ct, Iv8));
        });

    internal static void Assert_EncryptCbc_NonePadding_AllowInsecure_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedDes(backend, (workspace, des) =>
        {
            byte[] plaintext = new byte[16]; // exactly two 8-byte blocks
            RandomNumberGenerator.Fill(plaintext);

            workspace.AllowInsecure = true;
            using var bcl = BclDes();
            byte[] ct = OrSkipIfTokenLacksDes(() => des.EncryptCbc(plaintext, Iv8, PaddingMode.None));
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv8, PaddingMode.None), ct);
            Assert.Equal(plaintext, des.DecryptCbc(ct, Iv8, PaddingMode.None));
        });

    internal static void Assert_EncryptEcb_AllowInsecure_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedDes(backend, (workspace, des) =>
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

    internal static void Assert_EncryptCbc_UnsupportedPadding_Throws(IPkcs11Backend backend) =>
        WithImportedDes(backend, (_, des) =>
            Assert.Throws<NotSupportedException>(() => des.EncryptCbc(new byte[8], Iv8, PaddingMode.Zeros)));

    internal static void Assert_Cfb_NotSupported(IPkcs11Backend backend) =>
        WithImportedDes(backend, (workspace, des) =>
        {
            // DESPkcs11 does not override the CFB cores: the secure-defaults gate does not cover single-DES
            // CKM_DES_CFB*, so wiring it would bypass AllowInsecure. The base SymmetricAlgorithm surfaces
            // NotSupportedException — even with AllowInsecure set.
            workspace.AllowInsecure = true;
            Assert.Throws<NotSupportedException>(
                () => des.EncryptCfb(new byte[8], Iv8, PaddingMode.None, feedbackSizeInBits: 8));
        });

    internal static void Assert_GenerateIV_ProducesBlockSizedIv(IPkcs11Backend backend) =>
        WithImportedDes(backend, (_, des) =>
        {
            des.GenerateIV();
            Assert.Equal(8, des.IV.Length);
        });

    internal static void Assert_Cbc_EmptyInput_NoOp_ReturnsEmpty(IPkcs11Backend backend) =>
        WithImportedDes(backend, (workspace, des) =>
        {
            // The empty-input fast path honors the gate: without AllowInsecure the gated mechanism throws
            // before the (empty) buffer reaches the token (so no single-DES support is needed).
            Assert.Throws<InsecureOperationException>(() => des.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8));

            // With AllowInsecure, empty input is a no-op returned without touching the token.
            workspace.AllowInsecure = true;
            Assert.Empty(des.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8));
        });

    internal static void Assert_ManagedKeyAndStreamingSurface_NotSupported(IPkcs11Backend backend) =>
        WithImportedDes(backend, (_, des) =>
        {
            Assert.Throws<NotSupportedException>(() => des.CreateEncryptor(new byte[8], new byte[8]));
            Assert.Throws<NotSupportedException>(() => des.CreateDecryptor(new byte[8], new byte[8]));
            Assert.Throws<NotSupportedException>(() => des.GenerateKey());
            Assert.Throws<NotSupportedException>(() => des.Key);
        });
}
