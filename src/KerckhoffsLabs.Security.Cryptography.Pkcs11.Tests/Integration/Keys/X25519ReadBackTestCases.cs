using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// X25519 / X448 read-back with the token's real Montgomery arithmetic, which ManagedSoftToken cannot provide: two
/// parties read back the same raw shared secret, the RFC 7748 §6 test vectors give their published shared
/// secret, and low-order peers are refused.
/// </summary>
internal static class X25519ReadBackTestCases
{
    private static readonly byte[] X25519 = [0x06, 0x03, 0x2B, 0x65, 0x6E]; // 1.3.101.110
    private static readonly byte[] X448 = [0x06, 0x03, 0x2B, 0x65, 0x6F];   // 1.3.101.111

    /// <summary>
    /// Skips when the backend offers no X25519, unless the CI leg declares the backend expected
    /// (<paramref name="expectVariable"/> = 1): there the test is the only real-arithmetic coverage, so a
    /// missing mechanism fails rather than silently skipping.
    /// </summary>
    internal static void RequireX25519(bool supported, string backend, string? expectVariable)
    {
        if (supported)
            return;
        if (expectVariable is not null && Environment.GetEnvironmentVariable(expectVariable) == "1")
            Assert.Fail($"{backend}: this CI leg declares {expectVariable}=1, but the token offers no X25519 (CKM_EC_MONTGOMERY_KEY_PAIR_GEN).");
        Assert.Skip($"{backend}: X25519 (CKM_EC_MONTGOMERY_KEY_PAIR_GEN) not available");
    }

    // RFC 7748 §6.1 (X25519) and §6.2 (X448): Alice's private key, Bob's public key, and their shared secret.
    internal static void Assert_X25519KnownAnswer(Pkcs11Workspace workspace) => AssertKnownAnswer(workspace, "X25519", X25519,
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    internal static void Assert_X448KnownAnswer(Pkcs11Workspace workspace) => AssertKnownAnswer(workspace, "X448", X448,
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

    private static void AssertKnownAnswer(Pkcs11Workspace workspace, string curve, byte[] ecParams, string alicePrivate, string bobPublic, string shared)
    {
        using var export = workspace.UsePolicy(CryptoPolicy.Recommended.ToBuilder("Test")
            .AllowSecretExport(SecretExportKind.EcdhSharedSecret, $"{curve} known-answer test.").Build());
        Pkcs11Key alice;
        try
        {
            using var template = ObjectTemplate.ForPrivateKey(CKK.CKK_EC_MONTGOMERY)
                .Attribute(CKA.CKA_EC_PARAMS, ecParams)
                .Attribute(CKA.CKA_VALUE, Convert.FromHexString(alicePrivate))
                .Attribute(CKA.CKA_DERIVE, true)
                .Build();
            alice = workspace.ImportKey(template);
        }
        catch (Exceptions.Pkcs11Exception ex)
        {
            Assert.Skip($"The token does not import a raw {curve} private key ({ex.ReturnValue}).");
            return;
        }

        using (alice)
        {
            byte[] expected = Convert.FromHexString(shared);
            byte[] secret = new byte[expected.Length];
            alice.DeriveAndExportSecret(
                new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, Convert.FromHexString(bobPublic))), secret);
            Assert.Equal(expected, secret);
        }
    }

    // The library refuses a low-order peer before the token is called, for a read-back and on the token alike.
    internal static void Assert_LowOrderPeer_IsRefused(Pkcs11Workspace workspace)
    {
        using var lift = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
        using var key = Generate(workspace);
        using var aes = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Encrypt().Decrypt().Build();

        Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(
            new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, new byte[32])), new byte[32]));
        Assert.Throws<ArgumentException>(() => key.Derive(
            new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, [1, .. new byte[31]])), aes));
    }

    internal static void Assert_TwoParties_ReadBackTheSameSecret(Pkcs11Workspace workspace)
    {
        using var export = workspace.UsePolicy(CryptoPolicy.Recommended.ToBuilder("Test")
            .AllowSecretExport(SecretExportKind.EcdhSharedSecret, "Two-party X25519 agreement under test.").Build());
        using var alice = Generate(workspace);
        using var bob = Generate(workspace);
        byte[] alicePublic = PublicU(workspace, alice);
        byte[] bobPublic = PublicU(workspace, bob);

        byte[] aliceSecret = new byte[32];
        byte[] bobSecret = new byte[32];
        alice.DeriveAndExportSecret(new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, bobPublic)), aliceSecret);
        bob.DeriveAndExportSecret(new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, alicePublic)), bobSecret);

        Assert.Equal(aliceSecret, bobSecret);
        Assert.Contains(aliceSecret, b => b != 0);
    }

    private static Pkcs11Key Generate(Pkcs11Workspace workspace)
    {
        using var pub = ObjectTemplate.ForPublicKey(CKK.CKK_EC_MONTGOMERY).Attribute(CKA.CKA_EC_PARAMS, X25519).Build();
        using var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_EC_MONTGOMERY).Attribute(CKA.CKA_DERIVE, true).Build();
        return workspace.GenerateKeyPair(new Mechanism(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN), pub, priv);
    }

    private static byte[] PublicU(Pkcs11Workspace workspace, Pkcs11Key key)
    {
        using var attrs = workspace.Session.GetAttributeValue(key.PublicHandle, [CKA.CKA_EC_POINT]);
        Assert.False(attrs[0].CannotBeRead);
        return attrs[0].GetValueAsByteArray();
    }
}
