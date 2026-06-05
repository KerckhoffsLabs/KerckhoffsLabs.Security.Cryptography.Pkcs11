using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>ChaCha20Poly1305Pkcs11 over the in-process <c>ManagedSoftToken</c>, checked against the BCL
/// <see cref="ChaCha20Poly1305"/> for an imported known key.</summary>
public sealed class ChaCha20Poly1305Pkcs11Tests_Managed
{
    public static bool Supported => ChaCha20Poly1305.IsSupported;

    [ConditionalFact(nameof(Supported))]
    public void Encrypt_MatchesBcl_AndRoundTrips()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        byte[] keyBytes = RandomNumberGenerator.GetBytes(32);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_CHACHA20)
            .Label("chacha").Value(keyBytes).Encrypt().Decrypt().Build();
        using var key = workspace.ImportKey(tpl);
        using var chacha = new ChaCha20Poly1305Pkcs11(key);

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] aad = "aead-header"u8.ToArray();
        byte[] plaintext = RandomNumberGenerator.GetBytes(48);

        byte[] ct = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        chacha.Encrypt(nonce, plaintext, ct, tag, aad);

        byte[] bclCt = new byte[plaintext.Length];
        byte[] bclTag = new byte[16];
        using (var bcl = new ChaCha20Poly1305(keyBytes))
            bcl.Encrypt(nonce, plaintext, bclCt, bclTag, aad);
        Assert.Equal(bclCt, ct);
        Assert.Equal(bclTag, tag);

        byte[] decrypted = new byte[plaintext.Length];
        chacha.Decrypt(nonce, ct, tag, decrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }
}
