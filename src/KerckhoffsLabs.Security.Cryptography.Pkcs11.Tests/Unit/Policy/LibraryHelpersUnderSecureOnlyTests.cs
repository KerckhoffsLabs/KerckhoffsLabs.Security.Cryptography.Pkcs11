using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// ML-KEM / ML-DSA are evaluation-only BCL APIs (SYSLIB5006).
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>
/// The library's own key helpers and adapters must work under the default policy with no opt-in: an
/// allow-list that refused the library's recommended paths would push every consumer towards
/// <c>AllowInsecure</c>. Runs against the in-process <see cref="ManagedSoftToken"/>, with the workspace
/// opened under the default policy (no <c>UsePolicy</c> lease anywhere in this class).
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class LibraryHelpersUnderSecureOnlyTests
{
    private static readonly byte[] Message = Encoding.UTF8.GetBytes("secure-only helper payload");

    private static void WithWorkspace(Action<Pkcs11Workspace> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        Assert.Same(CryptoPolicy.SecureOnly, workspace.Policy);
        body(workspace);
    }

    [Fact]
    public void GenerateAesKey_AndAesGcmAdapter_RoundTrip() => WithWorkspace(workspace =>
    {
        using var key = workspace.GenerateAesKey();
        using var gcm = new AesGcmPkcs11(key, 16);

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[Message.Length];
        byte[] tag = new byte[16];
        gcm.Encrypt(nonce, Message, ciphertext, tag);

        byte[] plaintext = new byte[Message.Length];
        gcm.Decrypt(nonce, ciphertext, tag, plaintext);
        Assert.Equal(Message, plaintext);
    });

    // The managed token implements neither C_WrapKey nor C_UnwrapKey, so the wrap itself cannot run here
    // (it runs against the real backends in WrapUnwrapKeyTests). What this can prove on the managed token:
    // the KEK helper works, and the policy permits the helper's intended key-wrap mechanisms for it.
    [Fact]
    public void GenerateAesKeyEncryptionKey_AndItsWrapMechanisms_ArePermitted() => WithWorkspace(workspace =>
    {
        using var kek = workspace.GenerateAesKeyEncryptionKey();
        Assert.NotNull(kek);

        foreach (CKM wrap in (CKM[])[CKM.CKM_AES_KEY_WRAP_KWP, CKM.CKM_AES_KEY_WRAP, CKM.CKM_AES_KEY_WRAP_PAD])
        {
            Assert.True(workspace.IsPermitted(new MechanismUseRequest(new Mechanism(wrap), CryptoOperation.Wrap)), $"{wrap} Wrap");
            Assert.True(workspace.IsPermitted(new MechanismUseRequest(new Mechanism(wrap), CryptoOperation.Unwrap)), $"{wrap} Unwrap");
        }
    });

    [Fact]
    public void GenerateRsaSigningKeyPair_PssSignVerify() => WithWorkspace(workspace =>
    {
        using var key = workspace.GenerateRsaSigningKeyPair(2048);
        using var rsa = new RSAPkcs11(key);

        byte[] signature = rsa.SignData(Message, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.True(rsa.VerifyData(Message, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    });

    [Fact]
    public void GenerateRsaKeyTransportKeyPair_OaepSha256EncryptDecrypt() => WithWorkspace(workspace =>
    {
        using var key = workspace.GenerateRsaKeyTransportKeyPair(2048);
        using var rsa = new RSAPkcs11(key);

        byte[] ciphertext = rsa.Encrypt(Message, RSAEncryptionPadding.OaepSHA256);
        Assert.Equal(Message, rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256));
    });

    [Fact]
    public void GenerateEcKeyPair_EcdsaSha256SignVerify() => WithWorkspace(workspace =>
    {
        using var key = workspace.GenerateEcKeyPair();
        using var ecdsa = new ECDsaPkcs11(key);

        byte[] signature = ecdsa.SignData(Message, HashAlgorithmName.SHA256);
        Assert.True(ecdsa.VerifyData(Message, signature, HashAlgorithmName.SHA256));
    });

    // The managed token applies no KDF (it keys with the raw shared secret whatever CKD is passed), so this
    // proves the helper and its default CKD_SHA256_KDF pass the policy and agree across parties, not the
    // KDF itself; the real backends' DeriveSharedSecretEcdh tests cover that.
    [Fact]
    public void DeriveSharedSecretEcdh_DefaultKdf_TwoPartiesAgree() => WithWorkspace(workspace =>
    {
        using var alice = workspace.GenerateEcKeyPair();
        using var bob = workspace.GenerateEcKeyPair();
        byte[] alicePoint = ReadEcPoint(workspace, alice);
        byte[] bobPoint = ReadEcPoint(workspace, bob);

        using var aliceAes = workspace.DeriveSharedSecretEcdh(alice, bobPoint);
        using var bobAes = workspace.DeriveSharedSecretEcdh(bob, alicePoint);

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[Message.Length];
        byte[] tag = new byte[16];
        using (var sender = new AesGcmPkcs11(aliceAes, 16))
            sender.Encrypt(nonce, Message, ciphertext, tag);

        byte[] plaintext = new byte[Message.Length];
        using (var receiver = new AesGcmPkcs11(bobAes, 16))
            receiver.Decrypt(nonce, ciphertext, tag, plaintext);
        Assert.Equal(Message, plaintext);
    });

    private static byte[] ReadEcPoint(Pkcs11Workspace workspace, Pkcs11Key key)
    {
        using var attrs = workspace.Session.GetAttributeValue(key.PublicHandle, [CKA.CKA_EC_POINT]);
        return attrs[0].GetValueAsByteArray();
    }

    [Fact(SkipUnless = nameof(MLDsa.IsSupported), SkipType = typeof(MLDsa), Skip = "Requires " + nameof(MLDsa.IsSupported))]
    public void MlDsa_KeyGenerationAndAdapter_SignVerify() => WithWorkspace(workspace =>
    {
        string label = $"mldsa-{Guid.NewGuid():N}";
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA)
            .Label(label).Verify()
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlDsa.CKP_ML_DSA_65).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA).Label(label).Sign().Build();

        using var key = workspace.GenerateKeyPair(new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), pubTpl, privTpl);
        using var mldsa = new MLDsaPkcs11(key);

        byte[] signature = mldsa.SignData(Message);
        Assert.True(mldsa.VerifyData(Message, signature));
    });

    // The adapter's Encapsulate / Decapsulate read the shared secret off the token, which the default
    // policy refuses by design; the on-token path (EncapsulateKey / DecapsulateKey into sensitive keys)
    // is the one SecureOnly supports. The two AES keys are shown equal by an AES-GCM round trip across
    // them, without ever reading either value.
    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void MlKem_KeyGenerationAndOnTokenEncapsulation_AgreeOnAnAesKey() => WithWorkspace(workspace =>
    {
        string label = $"mlkem-{Guid.NewGuid():N}";
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Label(label)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlKem.CKP_ML_KEM_768).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Label(label)
            .Attribute(CKA.CKA_DECAPSULATE, true).Build();
        using var kemKey = workspace.GenerateKeyPair(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), pubTpl, privTpl);

        using var secretTpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Encrypt().Decrypt().Build();
        using EncapsulationResult encapsulated = kemKey.EncapsulateKey(new Mechanism(CKM.CKM_ML_KEM), secretTpl);
        using Pkcs11Key decapsulated = kemKey.DecapsulateKey(new Mechanism(CKM.CKM_ML_KEM), encapsulated.Ciphertext, secretTpl);

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[Message.Length];
        byte[] tag = new byte[16];
        using (var sender = new AesGcmPkcs11(encapsulated.SharedSecret, 16))
            sender.Encrypt(nonce, Message, ciphertext, tag);

        byte[] plaintext = new byte[Message.Length];
        using (var receiver = new AesGcmPkcs11(decapsulated, 16))
            receiver.Decrypt(nonce, ciphertext, tag, plaintext);
        Assert.Equal(Message, plaintext);
    });
}
