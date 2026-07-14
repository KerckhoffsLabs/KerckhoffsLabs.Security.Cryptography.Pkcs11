using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// TripleDESPkcs11 is [Obsolete] (64-bit block / Sweet32, NIST-deprecated); the secure-defaults gate is
// the point of the type, so KLPKCS11004 is suppressed deliberately at the use sites.
#pragma warning disable KLPKCS11004

/// <summary>
/// Backend-agnostic TripleDESPkcs11 tests: token 3DES-CBC/ECB matches the BCL for the same key, the
/// managed-key / streaming surface is NotSupported, and CBC/ECB are gated by the secure-defaults policy.
/// Cases skip where the backend does not advertise <c>CKM_DES3_CBC</c> (and a known-answer op that the
/// token advertises but does not implement is turned into a skip on <c>CKR_MECHANISM_INVALID</c>).
/// </summary>
internal static class TripleDESPkcs11TestCases
{
    // 24-byte three-key 3DES key with three distinct, non-weak DES subkeys (the BCL TripleDES setter
    // rejects keys that degenerate to single/double DES).
    private static readonly byte[] Key192 =
        Convert.FromHexString("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123");
    private static readonly byte[] Iv8 = Convert.FromHexString("1020304050607080");

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.Library.OpenWorkspace(backend.TokenLabel, CKU.CKU_USER, new SecurePin(backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    private static void WithImportedDes3(IPkcs11Backend backend, Action<Pkcs11Workspace, TripleDESPkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_DES3_CBC))
            throw new SkipTestException("Backend does not advertise CKM_DES3_CBC.");

        using var workspace = OpenWorkspace(backend);
        string label = $"des3-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_DES3)
            .Label(label).Value(Key192).Encrypt().Decrypt().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var des3 = new TripleDESPkcs11(key);
            body(workspace, des3);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // Translate a token that advertises but does not implement 3DES (FIPS build) into a skip.
    private static byte[] OrSkipIfTokenLacksDes3(Func<byte[]> tokenOp)
    {
        try
        {
            return tokenOp();
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_MECHANISM_INVALID)
        {
            throw new SkipTestException(
                "Token advertises 3DES but its operation path rejects CKM_DES3_* (FIPS build).");
        }
    }

    private static TripleDES BclDes3()
    {
        var bcl = TripleDES.Create();
        bcl.Key = Key192;
        return bcl;
    }

    internal static void Assert_Ctor_NonDes3Key_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"nondes3-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(32).Sign().OnToken().Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new TripleDESPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (workspace, des3) =>
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("3DES-CBC PKCS7 over a token key — variable length.");
            Assert.Throws<InsecureOperationException>(() => des3.EncryptCbc(plaintext, Iv8));

            workspace.AllowInsecure = true;
            using var bcl = BclDes3();
            byte[] ct = OrSkipIfTokenLacksDes3(() => des3.EncryptCbc(plaintext, Iv8)); // default PaddingMode.PKCS7
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv8), ct);
            Assert.Equal(plaintext, des3.DecryptCbc(ct, Iv8));
        });

    internal static void Assert_EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (workspace, des3) =>
        {
            byte[] plaintext = new byte[16]; // exactly two 8-byte blocks
            RandomNumberGenerator.Fill(plaintext);
            Assert.Throws<InsecureOperationException>(() => des3.EncryptCbc(plaintext, Iv8, PaddingMode.None));

            workspace.AllowInsecure = true;
            using var bcl = BclDes3();
            byte[] ct = OrSkipIfTokenLacksDes3(() => des3.EncryptCbc(plaintext, Iv8, PaddingMode.None));
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv8, PaddingMode.None), ct);
            Assert.Equal(plaintext, des3.DecryptCbc(ct, Iv8, PaddingMode.None));
        });

    internal static void Assert_EncryptEcb_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (_, des3) =>
            Assert.Throws<InsecureOperationException>(() => des3.EncryptEcb(new byte[8], PaddingMode.None)));

    internal static void Assert_EncryptEcb_WithAllowInsecure_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (workspace, des3) =>
        {
            workspace.AllowInsecure = true;
            byte[] plaintext = new byte[8];
            RandomNumberGenerator.Fill(plaintext);
            using var bcl = BclDes3();

            byte[] ct = OrSkipIfTokenLacksDes3(() => des3.EncryptEcb(plaintext, PaddingMode.None));
            Assert.Equal(bcl.EncryptEcb(plaintext, PaddingMode.None), ct);
            Assert.Equal(plaintext, des3.DecryptEcb(ct, PaddingMode.None));
        });

    internal static void Assert_KeySize_ReflectsTokenKeyLength(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (_, des3) => Assert.Equal(192, des3.KeySize));

    internal static void Assert_EncryptCbc_UnsupportedPadding_Throws(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (_, des3) =>
            Assert.Throws<NotSupportedException>(() => des3.EncryptCbc(new byte[8], Iv8, PaddingMode.Zeros)));

    internal static void Assert_Cfb_NotSupported(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (workspace, des3) =>
        {
            // TripleDESPkcs11 does not override the CFB cores: PKCS#11 defines no CKM_DES3_CFB mechanism,
            // so the base SymmetricAlgorithm surfaces NotSupportedException — even with AllowInsecure set.
            workspace.AllowInsecure = true;
            Assert.Throws<NotSupportedException>(
                () => des3.EncryptCfb(new byte[8], Iv8, PaddingMode.None, feedbackSizeInBits: 8));
        });

    internal static void Assert_GenerateIV_ProducesBlockSizedIv(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (_, des3) =>
        {
            des3.GenerateIV();
            Assert.Equal(8, des3.IV.Length);
        });

    internal static void Assert_Cbc_EmptyInput_NoOp_ReturnsEmpty(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (workspace, des3) =>
        {
            Assert.Throws<InsecureOperationException>(() => des3.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8));

            workspace.AllowInsecure = true;
            Assert.Empty(des3.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8));
        });

    internal static void Assert_ManagedKeyAndStreamingSurface_NotSupported(IPkcs11Backend backend) =>
        WithImportedDes3(backend, (_, des3) =>
        {
            Assert.Throws<NotSupportedException>(() => des3.CreateEncryptor(new byte[24], new byte[8]));
            Assert.Throws<NotSupportedException>(() => des3.CreateDecryptor(new byte[24], new byte[8]));
            Assert.Throws<NotSupportedException>(() => des3.GenerateKey());
            Assert.Throws<NotSupportedException>(() => des3.Key);
        });
}
