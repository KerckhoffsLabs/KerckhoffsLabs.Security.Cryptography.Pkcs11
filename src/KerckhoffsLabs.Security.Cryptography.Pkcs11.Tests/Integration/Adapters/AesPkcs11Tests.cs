using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>Backend-free argument tests for <see cref="AesPkcs11"/>.</summary>
public sealed class AesPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new AesPkcs11(key: null!));
}

/// <summary>
/// AesPkcs11 over SoftHSM: token-computed AES-CBC/ECB must match the BCL for the same key, the
/// managed-key/streaming surface is NotSupported, and ECB is gated by the secure-defaults policy.
/// </summary>
[Collection("SoftHsm")]
public sealed class AesPkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private static readonly byte[] Key256 =
        Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    private static readonly byte[] Iv16 =
        Convert.FromHexString("0F0E0D0C0B0A09080706050403020100");

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            workspace.Session.DestroyObject(k.PrivateHandle);
            k.Dispose();
        }
    }

    // Imports Key256 as a token AES key and hands a wrapping AesPkcs11 (and its workspace) to the body.
    private void WithImportedAes(Action<Pkcs11Workspace, AesPkcs11> body)
    {
        using var workspace = OpenWorkspace();
        string label = $"aes-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(Key256).Encrypt().Decrypt().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var aes = new AesPkcs11(key);
            body(workspace, aes);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    private static Aes BclAes()
    {
        var bcl = Aes.Create();
        bcl.Key = Key256;
        return bcl;
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonAesKey_Throws()
    {
        using var workspace = OpenWorkspace();
        string label = $"nonaes-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(32).Sign().OnToken().Build())
        {
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), [.. t.Attributes]);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new AesPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_Pkcs7_MatchesBclAndRoundTrips() => WithImportedAes((_, aes) =>
    {
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("AES-CBC PKCS7 over a token key — variable length.");
        using var bcl = BclAes();

        byte[] ct = aes.EncryptCbc(plaintext, Iv16); // default PaddingMode.PKCS7
        Assert.Equal(bcl.EncryptCbc(plaintext, Iv16), ct);
        Assert.Equal(plaintext, aes.DecryptCbc(ct, Iv16));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl() => WithImportedAes((workspace, aes) =>
    {
        byte[] plaintext = new byte[32]; // exactly two blocks
        RandomNumberGenerator.Fill(plaintext);

        // Raw CBC (CKM_AES_CBC, no padding/MAC) is gated by the secure-defaults policy; only
        // CKM_AES_CBC_PAD is permitted by default.
        Assert.Throws<InsecureOperationException>(() => aes.EncryptCbc(plaintext, Iv16, PaddingMode.None));

        workspace.AllowInsecure = true;
        using var bcl = BclAes();
        byte[] ct = aes.EncryptCbc(plaintext, Iv16, PaddingMode.None);
        Assert.Equal(bcl.EncryptCbc(plaintext, Iv16, PaddingMode.None), ct);
        Assert.Equal(plaintext, aes.DecryptCbc(ct, Iv16, PaddingMode.None));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptCbc_UnsupportedPadding_Throws() => WithImportedAes((_, aes) =>
        Assert.Throws<NotSupportedException>(() => aes.EncryptCbc(new byte[16], Iv16, PaddingMode.Zeros)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptEcb_GatedByDefault_Throws() => WithImportedAes((_, aes) =>
        Assert.Throws<InsecureOperationException>(() => aes.EncryptEcb(new byte[16], PaddingMode.None)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void EncryptEcb_WithAllowInsecure_MatchesBcl() => WithImportedAes((workspace, aes) =>
    {
        workspace.AllowInsecure = true;
        byte[] plaintext = new byte[16];
        RandomNumberGenerator.Fill(plaintext);
        using var bcl = BclAes();

        byte[] ct = aes.EncryptEcb(plaintext, PaddingMode.None);
        Assert.Equal(bcl.EncryptEcb(plaintext, PaddingMode.None), ct);
        Assert.Equal(plaintext, aes.DecryptEcb(ct, PaddingMode.None));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GenerateIV_ProducesBlockSizedIv() => WithImportedAes((_, aes) =>
    {
        aes.GenerateIV();
        Assert.Equal(16, aes.IV.Length);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ManagedKeyAndStreamingSurface_NotSupported() => WithImportedAes((ws, aes) =>
    {
        Assert.Throws<NotSupportedException>(() => aes.CreateEncryptor(new byte[32], new byte[16]));
        Assert.Throws<NotSupportedException>(() => aes.CreateDecryptor(new byte[32], new byte[16]));
        Assert.Throws<NotSupportedException>(() => aes.GenerateKey());
        Assert.Throws<NotSupportedException>(() => { _ = aes.Key; });
    });
}
