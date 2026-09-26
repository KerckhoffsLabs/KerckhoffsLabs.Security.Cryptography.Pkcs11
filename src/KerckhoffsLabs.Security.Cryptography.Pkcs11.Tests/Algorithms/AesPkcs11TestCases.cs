using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic AesPkcs11 tests: token AES-CBC/ECB must match the BCL for the same imported key,
/// CBC/ECB/CFB are gated by the secure-defaults policy (require the AllowInsecure policy), and the managed-key /
/// streaming surface is NotSupported. Cases that perform a real cipher op skip where the backend does
/// not advertise the mechanism; the gate and NotSupported cases run on any backend (they fire in
/// managed code before the token).
/// </summary>
internal static class AesPkcs11TestCases
{
    private static readonly byte[] Key256 =
        Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    private static readonly byte[] Iv16 =
        Convert.FromHexString("0F0E0D0C0B0A09080706050403020100");

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    // Imports Key256 as a token AES key and hands a wrapping AesPkcs11 (and its workspace) to the body.
    private static void WithImportedAes(IPkcs11Backend backend, Action<Pkcs11Workspace, AesPkcs11> body)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"aes-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(Key256).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
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

    internal static void Assert_Ctor_NonAesKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"nonaes-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(32).Sign().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new AesPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_EncryptCbc_Pkcs7_GatedByDefault_AllowInsecureMatchesBcl(IPkcs11Backend backend) =>
        WithImportedAes(backend, (workspace, aes) =>
        {
            backend.RequireMechanism(CKM.CKM_AES_CBC);
            byte[] plaintext = Encoding.UTF8.GetBytes("AES-CBC PKCS7 over a token key — variable length.");

            // CBC (even with PKCS7) is unauthenticated and gated by the secure-defaults policy.
            Assert.Throws<CryptoPolicyViolationException>(() => aes.EncryptCbc(plaintext, Iv16));

            using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
            using var bcl = BclAes();
            byte[] ct = aes.EncryptCbc(plaintext, Iv16); // default PaddingMode.PKCS7
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv16), ct);
            Assert.Equal(plaintext, aes.DecryptCbc(ct, Iv16));
        });

    internal static void Assert_EncryptCbc_NonePadding_GatedByDefault_AllowInsecureMatchesBcl(IPkcs11Backend backend) =>
        WithImportedAes(backend, (workspace, aes) =>
        {
            backend.RequireMechanism(CKM.CKM_AES_CBC);
            byte[] plaintext = new byte[32]; // exactly two blocks
            RandomNumberGenerator.Fill(plaintext);

            Assert.Throws<CryptoPolicyViolationException>(() => aes.EncryptCbc(plaintext, Iv16, PaddingMode.None));

            using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
            using var bcl = BclAes();
            byte[] ct = aes.EncryptCbc(plaintext, Iv16, PaddingMode.None);
            Assert.Equal(bcl.EncryptCbc(plaintext, Iv16, PaddingMode.None), ct);
            Assert.Equal(plaintext, aes.DecryptCbc(ct, Iv16, PaddingMode.None));
        });

    internal static void Assert_Cfb_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithImportedAes(backend, (_, aes) =>
            Assert.Throws<CryptoPolicyViolationException>(
                () => aes.EncryptCfb(new byte[16], Iv16, PaddingMode.None, feedbackSizeInBits: 128)));

    internal static void Assert_Cfb_WithAllowInsecure_GateBypassed(IPkcs11Backend backend) =>
        WithImportedAes(backend, (workspace, aes) =>
        {
            using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
            // The token may not implement CFB, so the call may fail — but the secure-defaults gate must
            // NOT fire once the AllowInsecure policy is used.
            Exception? ex = Record.Exception(
                () => aes.EncryptCfb(new byte[16], Iv16, PaddingMode.None, feedbackSizeInBits: 128));
            Assert.False(ex is CryptoPolicyViolationException,
                $"Gate should be bypassed; got {ex?.GetType().Name ?? "no exception"}.");
        });

    internal static void Assert_Cfb_NonNonePadding_Throws(IPkcs11Backend backend) =>
        WithImportedAes(backend, (_, aes) =>
            Assert.Throws<NotSupportedException>(
                () => aes.EncryptCfb(new byte[16], Iv16, PaddingMode.PKCS7, feedbackSizeInBits: 128)));

    internal static void Assert_EncryptCbc_UnsupportedPadding_Throws(IPkcs11Backend backend) =>
        WithImportedAes(backend, (_, aes) =>
            Assert.Throws<NotSupportedException>(() => aes.EncryptCbc(new byte[16], Iv16, PaddingMode.Zeros)));

    internal static void Assert_EncryptEcb_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithImportedAes(backend, (_, aes) =>
            Assert.Throws<CryptoPolicyViolationException>(() => aes.EncryptEcb(new byte[16], PaddingMode.None)));

    internal static void Assert_EncryptEcb_WithAllowInsecure_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedAes(backend, (workspace, aes) =>
        {
            backend.RequireMechanism(CKM.CKM_AES_ECB);
            using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
            byte[] plaintext = new byte[16];
            RandomNumberGenerator.Fill(plaintext);
            using var bcl = BclAes();

            byte[] ct = aes.EncryptEcb(plaintext, PaddingMode.None);
            Assert.Equal(bcl.EncryptEcb(plaintext, PaddingMode.None), ct);
            Assert.Equal(plaintext, aes.DecryptEcb(ct, PaddingMode.None));
        });

    internal static void Assert_GenerateIV_ProducesBlockSizedIv(IPkcs11Backend backend) =>
        WithImportedAes(backend, (_, aes) =>
        {
            aes.GenerateIV();
            Assert.Equal(16, aes.IV.Length);
        });

    internal static void Assert_KeySize_ReflectsTokenKeyLength(IPkcs11Backend backend, int keyBytes, int expectedBits)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"aes-ks-{Guid.NewGuid():N}";
        byte[] raw = new byte[keyBytes];
        RandomNumberGenerator.Fill(raw);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(raw).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var aes = new AesPkcs11(key);
            Assert.Equal(expectedBits, aes.KeySize);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_Cbc_EmptyInput_NoOp_ReturnsEmpty(IPkcs11Backend backend) =>
        WithImportedAes(backend, (workspace, aes) =>
        {
            // The empty-input fast path still honors the gate: without the AllowInsecure policy the gated mechanism
            // throws before the (empty) buffer reaches the token.
            Assert.Throws<CryptoPolicyViolationException>(() => aes.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv16));

            // Under the AllowInsecure policy, empty input is a no-op returned without touching the token.
            using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
            Assert.Empty(aes.DecryptCbc(ReadOnlySpan<byte>.Empty, Iv16));
        });

    internal static void Assert_ManagedKeyAndStreamingSurface_NotSupported(IPkcs11Backend backend) =>
        WithImportedAes(backend, (_, aes) =>
        {
            Assert.Throws<NotSupportedException>(() => aes.CreateEncryptor(new byte[32], new byte[16]));
            Assert.Throws<NotSupportedException>(() => aes.CreateDecryptor(new byte[32], new byte[16]));
            Assert.Throws<NotSupportedException>(() => aes.GenerateKey());
            Assert.Throws<NotSupportedException>(() => aes.Key);
        });
}
