using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

#pragma warning disable KLPKCS11008 // CKM_RSA_PKCS encryption is refused on purpose here

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Security;

/// <summary>
/// Backend-agnostic checks of <see cref="CryptoPolicy.FipsOnly"/> on a real token: approved mechanisms
/// reach the module and work, and refused ones are stopped before it.
/// </summary>
internal static class FipsOnlyPolicyTestCases
{
    // A FipsOnly session over the backend's own authentication model (no login on NSS's public token).
    private static Pkcs11Session OpenFips(IPkcs11Backend backend) =>
        backend.RequiresUserLogin
            ? backend.Library.OpenSessionWithPin(backend.TokenLabel, CKU.CKU_USER, new SecurePin(backend.UserPin.Span), CryptoPolicy.FipsOnly)
            : backend.Library.OpenSessionWithoutLogin(backend.TokenLabel, CryptoPolicy.FipsOnly);

    internal static void Assert_AesGcm_RoundTrips(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_GCM);
        using var session = OpenFips(backend);
        using var key = session.GenerateAesKey(256);
        // Random, not all zero: Craton HSM refuses an all-zero GCM IV, and one already used with the key.
        byte[] iv = RandomNumberGenerator.GetBytes(12);
        byte[] plaintext = [1, 2, 3, 4];

        byte[] ct = key.Encrypt(new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(iv, [], 128)), plaintext);
        byte[] pt = key.Decrypt(new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(iv, [], 128)), ct);

        Assert.Equal(plaintext, pt);
    }

    internal static void Assert_RsaPss_Signs(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS_PSS);
        using var session = OpenFips(backend);
        using var key = session.GenerateRsaSigningKeyPair(2048);
        var pss = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));

        byte[] signature = key.Sign(pss, [1, 2, 3]);

        Assert.Equal(256, signature.Length);
    }

    internal static void Assert_ChaCha20Poly1305_IsRefused_BeforeTheToken(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        using var session = OpenFips(backend);
        using var key = session.GenerateAesKey(256); // any key: the refusal happens before C_EncryptInit

        var ex = Assert.Throws<CryptoPolicyViolationException>(
            () => key.Encrypt(new Mechanism(CKM.CKM_CHACHA20_POLY1305), [1]));

        Assert.Equal("FipsOnly", ex.PolicyName);
        Assert.Equal(CKM.CKM_CHACHA20_POLY1305, ex.Mechanism);
    }

    internal static void Assert_RsaPkcs1v15Encryption_IsRefused(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        using var session = OpenFips(backend);
        using var key = session.GenerateRsaKeyTransportKeyPair(2048);

        var ex = Assert.Throws<CryptoPolicyViolationException>(
            () => key.Encrypt(new Mechanism(CKM.CKM_RSA_PKCS), [1]));

        Assert.Equal("FipsOnly", ex.PolicyName);
    }
}
