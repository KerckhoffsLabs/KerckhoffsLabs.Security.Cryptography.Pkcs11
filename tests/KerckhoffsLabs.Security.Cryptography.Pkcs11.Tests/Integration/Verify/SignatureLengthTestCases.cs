using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

/// <summary>
/// A signature or MAC of the wrong length is an invalid signature: verify returns <see langword="false"/>, as the
/// BCL does, never throws, and the session stays usable.
/// </summary>
/// <remarks>
/// Backends disagree on how they report it. SoftHSM2 (<c>AsymVerify</c>/<c>MacVerify</c>) and Kryoptic
/// (<c>fns/signing.rs</c>) answer CKR_SIGNATURE_LEN_RANGE, which the spec defines as "invalid purely on the
/// basis of its length". NSS since 3.126 (68af90f46, Bug 2054695) compares only <c>min(macLen, sigLen)</c>
/// bytes of a non-general HMAC and leaves the length check to the caller, so on its own it accepts a
/// truncated or even empty MAC as valid. Each case therefore covers a truncated, an over-long and an empty
/// value, then a valid one on the same session.
/// </remarks>
internal static class SignatureLengthTestCases
{
    private static readonly byte[] Data = Encoding.ASCII.GetBytes("signature length");

    private static IEnumerable<byte[]> WrongLengths(byte[] valid) =>
    [
        valid[..(valid.Length / 2)],
        valid[..^1],
        [.. valid, 0x00],
        [],
    ];

    private static void DestroyByLabel(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in session.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    internal static void Assert_EcDsa_WrongLengthSignature_ReturnsFalse(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_EC_KEY_PAIR_GEN) || !backend.Supports(CKM.CKM_ECDSA))
            Assert.Skip("Backend does not advertise CKM_EC_KEY_PAIR_GEN + CKM_ECDSA.");

        using var session = backend.OpenSession();
        string label = $"siglen-ec-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC).Label(label).Id(id).Verify().EcParams(TestKeys.EcP256Oid).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Label(label).Id(id).Sign().Build();
        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            using var ec = new ECDsaPkcs11(key);
            byte[] signature = ec.SignData(Data, HashAlgorithmName.SHA256);
            byte[] hash = SHA256.HashData(Data);

            foreach (byte[] wrong in WrongLengths(signature))
            {
                Assert.False(ec.VerifyData(Data, wrong, HashAlgorithmName.SHA256), $"VerifyData accepted a {wrong.Length}-byte signature.");
                Assert.False(ec.VerifyHash(hash, wrong), $"VerifyHash accepted a {wrong.Length}-byte signature.");
            }

            Assert.True(ec.VerifyData(Data, signature, HashAlgorithmName.SHA256));
        }
        finally
        {
            try { key.Destroy(); } catch { /* best-effort cleanup */ }
        }
    }

    internal static void Assert_Rsa_WrongLengthSignature_ReturnsFalse(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        using var session = backend.OpenSession();
        string label = $"siglen-rsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048).PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA).Label(label).Id(id).Sign().Build();
        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            using var rsa = new RSAPkcs11(key);
            byte[] signature = rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            foreach (byte[] wrong in WrongLengths(signature))
                Assert.False(rsa.VerifyData(Data, wrong, HashAlgorithmName.SHA256, RSASignaturePadding.Pss), $"VerifyData accepted a {wrong.Length}-byte signature.");

            Assert.True(rsa.VerifyData(Data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        }
        finally
        {
            try { key.Destroy(); } catch { /* best-effort cleanup */ }
        }
    }

    internal static void Assert_Hmac_WrongLengthMac_ReturnsFalse(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        byte[] rawKey = RandomNumberGenerator.GetBytes(32);
        byte[] mac = HMACSHA256.HashData(rawKey, Data);

        using var session = backend.OpenSession();
        string label = $"siglen-hmac-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(rawKey).Sign().Verify().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = session.ImportKey(tpl);
            var mechanism = new Mechanism(CKM.CKM_SHA256_HMAC);

            foreach (byte[] wrong in WrongLengths(mac))
                Assert.False(key.Verify(mechanism, Data, wrong), $"Verify accepted a {wrong.Length}-byte MAC.");

            Assert.True(key.Verify(mechanism, Data, mac));
        }
        finally { DestroyByLabel(session, label); }
    }
}
