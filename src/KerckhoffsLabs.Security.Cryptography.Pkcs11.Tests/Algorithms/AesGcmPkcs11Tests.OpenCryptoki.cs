using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// AES-GCM against a second real backend (opencryptoki). Cross-implementation coverage: the same
/// adapter path validated on SoftHSM is re-run here so a shared mis-encoding surfaces.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class AesGcmPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private static byte[] Iota(int length)
    {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) b[i] = (byte)i;
        return b;
    }

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter)) { k.Delete(); k.Dispose(); }
    }

    private void WithGcm(Action<AesGcmPkcs11> body)
    {
        if (!_backend.Supports(CKM.CKM_AES_GCM))
            throw new SkipTestException("opencryptoki: CKM_AES_GCM not available");
        using var workspace = OpenWorkspace();
        string label = $"octk-gcm-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            using var gcm = new AesGcmPkcs11(key);
            body(gcm);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    [ConditionalFact(nameof(Available))]
    public void EncryptDecrypt_RoundTrips() => WithGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] aad = Encoding.UTF8.GetBytes("opencryptoki aad");
        byte[] plaintext = Encoding.UTF8.GetBytes("cross-backend gcm payload");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        byte[] decrypted = new byte[plaintext.Length];
        gcm.Decrypt(nonce, ciphertext, tag, decrypted, aad);

        Assert.Equal(plaintext, decrypted);
    });

    [ConditionalFact(nameof(Available))]
    public void Decrypt_TamperedTag_Throws() => WithGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = Encoding.UTF8.GetBytes("authenticity");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag);
        tag[0] ^= 0xFF;

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Pkcs11Exception>(() => gcm.Decrypt(nonce, ciphertext, tag, dest));
    });

    // opencryptoki's AES-GCM authentication-failure return code may differ from SoftHSM's
    // CKR_ENCRYPTED_DATA_INVALID, so these assert the exception type (a Pkcs11Exception, not a crash)
    // rather than pinning the exact CKR — the point is that the second backend genuinely rejects the
    // forgery instead of silently returning garbage.
    [ConditionalFact(nameof(Available))]
    public void Decrypt_TamperedCiphertext_Throws() => WithGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = Encoding.UTF8.GetBytes("integrity matters");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag);
        ciphertext[0] ^= 0xFF;

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Pkcs11Exception>(() => gcm.Decrypt(nonce, ciphertext, tag, dest));
    });

    [ConditionalFact(nameof(Available))]
    public void Decrypt_WrongAad_Throws() => WithGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = Encoding.UTF8.GetBytes("bound to its aad");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes("aad-A"));

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Pkcs11Exception>(() =>
            gcm.Decrypt(nonce, ciphertext, tag, dest, Encoding.UTF8.GetBytes("aad-B")));
    });

    [ConditionalFact(nameof(Available))]
    public void Decrypt_WrongNonce_Throws() => WithGcm(gcm =>
    {
        byte[] nonce = Iota(12);
        byte[] plaintext = Encoding.UTF8.GetBytes("nonce bound");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag);
        byte[] wrongNonce = Iota(12);
        wrongNonce[0] ^= 0xFF;

        byte[] dest = new byte[plaintext.Length];
        Assert.ThrowsAny<Pkcs11Exception>(() => gcm.Decrypt(wrongNonce, ciphertext, tag, dest));
    });
}
