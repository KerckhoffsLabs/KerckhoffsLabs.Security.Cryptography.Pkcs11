using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// AesGcmPkcs11 over the in-process <c>ManagedSoftToken</c>. The token reports no message API, so the
/// adapter uses its v2.40 single-part path (ciphertext ‖ tag). Output is checked against the BCL
/// <see cref="AesGcm"/> for an imported known key, then round-tripped.
/// </summary>
public sealed class AesGcmPkcs11Tests_Managed
{
    [Fact]
    public void Encrypt_MatchesBclAesGcm_AndRoundTrips()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        byte[] keyBytes = RandomNumberGenerator.GetBytes(32);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("gcm").Value(keyBytes).Encrypt().Decrypt().Build();
        using var key = workspace.ImportKey(tpl);
        using var gcm = new AesGcmPkcs11(key);

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] aad = "authenticated-header"u8.ToArray();
        byte[] plaintext = RandomNumberGenerator.GetBytes(40);

        byte[] ct = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        gcm.Encrypt(nonce, plaintext, ct, tag, aad);

        byte[] bclCt = new byte[plaintext.Length];
        byte[] bclTag = new byte[16];
        using (var bcl = new AesGcm(keyBytes, 16))
            bcl.Encrypt(nonce, plaintext, bclCt, bclTag, aad);
        Assert.Equal(bclCt, ct);
        Assert.Equal(bclTag, tag);

        byte[] decrypted = new byte[plaintext.Length];
        gcm.Decrypt(nonce, ct, tag, decrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }
}
