using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// TripleDESPkcs11 is [Obsolete] (64-bit block / Sweet32, NIST-deprecated); the secure-defaults gate
// is the point of the type, so CS0618 is suppressed deliberately at the use sites.
#pragma warning disable CS0618

/// <summary>Backend-free argument tests for <see cref="TripleDESPkcs11"/>.</summary>
public sealed class TripleDESPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new TripleDESPkcs11(key: null!));
}

/// <summary>
/// TripleDESPkcs11 over SoftHSM: token-computed 3DES-CBC/ECB must match the BCL for the same key, the
/// managed-key/streaming surface is NotSupported, CFB is NotSupported, and every mode is gated by the
/// secure-defaults policy. Unlike single DES, SoftHSM implements <c>CKM_DES3_*</c>, so the
/// known-answer round-trips run rather than skip.
/// </summary>
[Collection("SoftHsm")]
public sealed class TripleDESPkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    // 24-byte three-key 3DES key with three distinct, non-weak DES subkeys, so the BCL TripleDES key
    // setter accepts it (it rejects keys that degenerate to single/double DES) for the KAT comparison.
    private static readonly byte[] Key192 =
        Convert.FromHexString("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123");
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

    // Imports Key192 as a token 3DES key and hands a wrapping TripleDESPkcs11 (and its workspace) to the body.
    private void WithImportedDes3(Action<Pkcs11Workspace, TripleDESPkcs11> body)
    {
        using var workspace = OpenWorkspace();
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

    private static TripleDES BclDes3()
    {
        var bcl = TripleDES.Create();
        bcl.Key = Key192;
        return bcl;
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonDes3Key_Throws()
    {
        using var workspace = OpenWorkspace();
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

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl() => WithImportedDes3((workspace, des3) =>
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("3DES-CBC PKCS7 over a token key — variable length.");

        // 3DES is deprecated and every mode is gated by the secure-defaults policy.
        Assert.Throws<InsecureOperationException>(() => des3.EncryptCbc(plaintext, Iv8));

        workspace.AllowInsecure = true;
        using var bcl = BclDes3();
        byte[] ct = des3.EncryptCbc(plaintext, Iv8); // default PaddingMode.PKCS7
        Assert.Equal(bcl.EncryptCbc(plaintext, Iv8), ct);
        Assert.Equal(plaintext, des3.DecryptCbc(ct, Iv8));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl() => WithImportedDes3((workspace, des3) =>
    {
        byte[] plaintext = new byte[16]; // exactly two 8-byte blocks
        RandomNumberGenerator.Fill(plaintext);

        Assert.Throws<InsecureOperationException>(() => des3.EncryptCbc(plaintext, Iv8, PaddingMode.None));

        workspace.AllowInsecure = true;
        using var bcl = BclDes3();
        byte[] ct = des3.EncryptCbc(plaintext, Iv8, PaddingMode.None);
        Assert.Equal(bcl.EncryptCbc(plaintext, Iv8, PaddingMode.None), ct);
        Assert.Equal(plaintext, des3.DecryptCbc(ct, Iv8, PaddingMode.None));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptEcb_GatedByDefault_Throws() => WithImportedDes3((_, des3) =>
        Assert.Throws<InsecureOperationException>(() => des3.EncryptEcb(new byte[8], PaddingMode.None)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptEcb_WithAllowInsecure_MatchesBcl() => WithImportedDes3((workspace, des3) =>
    {
        workspace.AllowInsecure = true;
        byte[] plaintext = new byte[8];
        RandomNumberGenerator.Fill(plaintext);
        using var bcl = BclDes3();

        byte[] ct = des3.EncryptEcb(plaintext, PaddingMode.None);
        Assert.Equal(bcl.EncryptEcb(plaintext, PaddingMode.None), ct);
        Assert.Equal(plaintext, des3.DecryptEcb(ct, PaddingMode.None));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void KeySize_ReflectsTokenKeyLength() => WithImportedDes3((_, des3) =>
        Assert.Equal(192, des3.KeySize));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_UnsupportedPadding_Throws() => WithImportedDes3((_, des3) =>
        Assert.Throws<NotSupportedException>(() => des3.EncryptCbc(new byte[8], Iv8, PaddingMode.Zeros)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Cfb_NotSupported() => WithImportedDes3((workspace, des3) =>
    {
        // TripleDESPkcs11 does not override the CFB cores: PKCS#11 defines no CKM_DES3_CFB mechanism,
        // so the base SymmetricAlgorithm surfaces NotSupportedException — even with AllowInsecure set.
        workspace.AllowInsecure = true;
        Assert.Throws<NotSupportedException>(
            () => des3.EncryptCfb(new byte[8], Iv8, PaddingMode.None, feedbackSizeInBits: 8));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateIV_ProducesBlockSizedIv() => WithImportedDes3((_, des3) =>
    {
        des3.GenerateIV();
        Assert.Equal(8, des3.IV.Length);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Cbc_EmptyInput_NoOp_ReturnsEmpty() => WithImportedDes3((_, des3) =>
    {
        // Empty input that yields empty output is a no-op returned without touching the token
        // (so it does not trip SoftHSM's empty-buffer rejection on CKM_DES3_CBC / CKM_DES3_CBC_PAD).
        Assert.Empty(des3.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv8));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => WithImportedDes3((ws, des3) =>
    {
        Assert.Throws<NotSupportedException>(() => des3.CreateEncryptor(new byte[24], new byte[8]));
        Assert.Throws<NotSupportedException>(() => des3.CreateDecryptor(new byte[24], new byte[8]));
        Assert.Throws<NotSupportedException>(() => des3.GenerateKey());
        Assert.Throws<NotSupportedException>(() => { _ = des3.Key; });
    });
}
