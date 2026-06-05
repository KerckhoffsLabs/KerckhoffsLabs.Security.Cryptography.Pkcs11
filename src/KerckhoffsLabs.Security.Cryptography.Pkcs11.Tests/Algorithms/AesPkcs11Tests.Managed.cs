using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Proof that the <c>Algorithms</c> adapters can be exercised against a fully managed
/// <c>ILowLevelPkcs11Library</c> fake — no SoftHSM, no native module. Drives
/// <see cref="AesPkcs11"/> over <see cref="ManagedSoftToken"/> end-to-end: open workspace →
/// generate / import an AES key → CBC/ECB encrypt-decrypt, with the token performing the crypto
/// in managed code via the BCL. This is the template for covering mechanism families SoftHSM lacks
/// (single-DES, RC2, SHA-3, SP800-108, ML-DSA/ML-KEM/SLH-DSA) without skip-gating.
/// (Backend sibling of <c>AesPkcs11Tests.cs</c> / <c>AesPkcs11Tests.SoftHsm2.cs</c>.)
/// </summary>
public sealed class AesPkcs11Tests_Managed
{
    [Fact]
    public void AesCbcPkcs7_RoundTrips_OverManagedToken()
    {
        using var library = new Pkcs11Library(new ManagedSoftToken());
        using var workspace = library.OpenWorkspace(ManagedSoftToken.TokenLabel, CKU.CKU_USER, new SecurePin("1234"));
        workspace.AllowInsecure = true;

        using var key = workspace.GenerateAesKey(256);
        using var aes = new AesPkcs11(key);

        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] plaintext = "the managed token performs real AES-CBC via the BCL"u8.ToArray();

        byte[] ciphertext = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
        byte[] recovered = aes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);

        Assert.Equal(plaintext, recovered);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    public void AesCbcNoPadding_BlockAligned_RoundTrips()
    {
        using var library = new Pkcs11Library(new ManagedSoftToken());
        using var workspace = library.OpenWorkspace(ManagedSoftToken.TokenLabel, CKU.CKU_USER, new SecurePin("1234"));
        workspace.AllowInsecure = true;

        using var key = workspace.GenerateAesKey(128);
        using var aes = new AesPkcs11(key);

        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] plaintext = RandomNumberGenerator.GetBytes(32); // 2 blocks, no padding needed

        byte[] ciphertext = aes.EncryptCbc(plaintext, iv, PaddingMode.None);
        byte[] recovered = aes.DecryptCbc(ciphertext, iv, PaddingMode.None);

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void AesEcb_RoundTrips_OverManagedToken()
    {
        using var library = new Pkcs11Library(new ManagedSoftToken());
        using var workspace = library.OpenWorkspace(ManagedSoftToken.TokenLabel, CKU.CKU_USER, new SecurePin("1234"));
        workspace.AllowInsecure = true;

        using var key = workspace.GenerateAesKey(256);
        using var aes = new AesPkcs11(key);

        byte[] plaintext = RandomNumberGenerator.GetBytes(48); // 3 blocks
        byte[] ciphertext = aes.EncryptEcb(plaintext, PaddingMode.None);
        byte[] recovered = aes.DecryptEcb(ciphertext, PaddingMode.None);

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void KnownKey_TokenOutput_MatchesBcl()
    {
        // Import a key with a KNOWN value (C_CreateObject) and compare the token's CBC output to the
        // BCL with the same key + IV — a true known-answer check that a non-extractable SoftHSM key
        // can't give you. This is the kind of assertion the managed token unlocks.
        using var library = new Pkcs11Library(new ManagedSoftToken());
        using var workspace = library.OpenWorkspace(ManagedSoftToken.TokenLabel, CKU.CKU_USER, new SecurePin("1234"));
        workspace.AllowInsecure = true;

        byte[] keyBytes = RandomNumberGenerator.GetBytes(32);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("kat-key").Value(keyBytes).Encrypt().Decrypt().Build();
        using var key = workspace.ImportKey(template);
        using var aes = new AesPkcs11(key);

        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] plaintext = RandomNumberGenerator.GetBytes(64);

        byte[] viaPkcs11 = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);

        using var bcl = Aes.Create();
        bcl.Key = keyBytes;
        byte[] viaBcl = bcl.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);

        Assert.Equal(viaBcl, viaPkcs11);
    }
}
