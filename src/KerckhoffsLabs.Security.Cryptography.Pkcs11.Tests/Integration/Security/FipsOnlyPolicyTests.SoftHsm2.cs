using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

#pragma warning disable KLPKCS11008 // CKM_RSA_PKCS encryption is refused on purpose here

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

[Collection("SoftHsm")]
public sealed class FipsOnlyPolicyTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    private Pkcs11Workspace OpenFips() =>
        _backend.Library.OpenWorkspaceWithPin(_backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span), CryptoPolicy.FipsOnly);

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void AesGcm_RoundTrips()
    {
        using var workspace = OpenFips();
        using var key = workspace.GenerateAesKey(256);
        byte[] iv = new byte[12];
        byte[] plaintext = [1, 2, 3, 4];

        byte[] ct = key.Encrypt(new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(iv, [], 128)), plaintext);
        byte[] pt = key.Decrypt(new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(iv, [], 128)), ct);

        Assert.Equal(plaintext, pt);
    }

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void RsaPss_Signs()
    {
        using var workspace = OpenFips();
        using var key = workspace.GenerateRsaSigningKeyPair(2048);
        var pss = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));

        byte[] signature = key.Sign(pss, [1, 2, 3]);

        Assert.Equal(256, signature.Length);
    }

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void ChaCha20Poly1305_IsRefused_BeforeTheToken()
    {
        using var workspace = OpenFips();
        using var key = workspace.GenerateAesKey(256); // any key: the refusal happens before C_EncryptInit

        var ex = Assert.Throws<CryptoPolicyViolationException>(
            () => key.Encrypt(new Mechanism(CKM.CKM_CHACHA20_POLY1305), [1]));

        Assert.Equal("FipsOnly", ex.PolicyName);
        Assert.Equal(CKM.CKM_CHACHA20_POLY1305, ex.Mechanism);
    }

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void RsaPkcs1v15Encryption_IsRefused()
    {
        using var workspace = OpenFips();
        using var key = workspace.GenerateRsaKeyTransportKeyPair(2048);

        var ex = Assert.Throws<CryptoPolicyViolationException>(
            () => key.Encrypt(new Mechanism(CKM.CKM_RSA_PKCS), [1]));

        Assert.Equal("FipsOnly", ex.PolicyName);
    }
}
