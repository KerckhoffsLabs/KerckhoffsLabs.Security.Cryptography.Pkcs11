using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>AesCcmPkcs11 over the in-process <c>ManagedSoftToken</c>, checked against the BCL
/// <see cref="AesCcm"/> for an imported known key.</summary>
public sealed class AesCcmPkcs11Tests_Managed
{
    [Fact]
    public void Encrypt_MatchesBclAesCcm_AndRoundTrips()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        byte[] keyBytes = RandomNumberGenerator.GetBytes(32);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("ccm").Value(keyBytes).Encrypt().Decrypt().Build();
        using var key = workspace.ImportKey(tpl);
        using var ccm = new AesCcmPkcs11(key);

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] aad = "ccm-header"u8.ToArray();
        byte[] plaintext = RandomNumberGenerator.GetBytes(32);

        byte[] ct = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        ccm.Encrypt(nonce, plaintext, ct, tag, aad);

        byte[] bclCt = new byte[plaintext.Length];
        byte[] bclTag = new byte[16];
        using (var bcl = new AesCcm(keyBytes))
            bcl.Encrypt(nonce, plaintext, bclCt, bclTag, aad);
        Assert.Equal(bclCt, ct);
        Assert.Equal(bclTag, tag);

        byte[] decrypted = new byte[plaintext.Length];
        ccm.Decrypt(nonce, ct, tag, decrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }
}
