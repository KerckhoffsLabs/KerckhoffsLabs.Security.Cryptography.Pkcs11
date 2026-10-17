using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>
/// Zero-length input through the BCL adapters on every real backend: the result must match the BCL and the
/// session must stay usable for the next operation of the same kind.
/// </summary>
/// <remarks>
/// A zero-length span pinned with a bare <c>fixed</c> yields a NULL pointer, and several modules reject
/// <c>pData == NULL</c> even with a zero length: SoftHSM2 returns CKR_ARGUMENTS_BAD from C_Digest/C_Sign/C_Verify
/// before it looks the session up, so the operation is left active (upstream a8d6c5f/a906a8b fixed only the
/// encrypt/decrypt half); Kryoptic keeps the NULL check on purpose (926417f allows a non-NULL zero-length
/// buffer); opencryptoki rejects it in its one-shot entry points. Each case therefore runs the operation twice
/// on the same session — an empty input followed by a non-empty one — so a left-over active operation shows up
/// as CKR_OPERATION_ACTIVE on the second call.
/// </remarks>
internal static class EmptyInputTestCases
{
    private static readonly byte[] Abc = Encoding.ASCII.GetBytes("abc");
    private static readonly byte[] Empty = [];

    private static void DestroyByLabel(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in session.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    internal static void Assert_Sha256_EmptyInput_MatchesBcl_SessionReusable(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256);
        using var session = backend.OpenSession();
        using var sha = new SHA256Pkcs11(session);

        Assert.Equal(SHA256.HashData(Empty), sha.ComputeHash(Empty));
        Assert.Equal(SHA256.HashData(Abc), sha.ComputeHash(Abc));
    }

    internal static void Assert_Hmac_EmptyInput_MatchesBcl_SessionReusable(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        byte[] rawKey = RandomNumberGenerator.GetBytes(32);
        using var session = backend.OpenSession();
        string label = $"empty-hmac-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(rawKey).Sign().Verify().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = session.ImportKey(tpl);
            using var hmac = new HMACPkcs11(key, HashAlgorithmName.SHA256);

            Assert.Equal(HMACSHA256.HashData(rawKey, Empty), hmac.ComputeHash(Empty));
            Assert.Equal(HMACSHA256.HashData(rawKey, Abc), hmac.ComputeHash(Abc));
        }
        finally { DestroyByLabel(session, label); }
    }

    internal static void Assert_EcDsa_EmptyData_SignVerify_MatchesBcl_SessionReusable(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_EC_KEY_PAIR_GEN) || !backend.Supports(CKM.CKM_ECDSA))
            Assert.Skip("Backend does not advertise CKM_EC_KEY_PAIR_GEN + CKM_ECDSA.");

        using var session = backend.OpenSession();
        string label = $"empty-ec-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC).Label(label).Id(id).Verify().EcParams(TestKeys.EcP256Oid).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Label(label).Id(id).Sign().Build();
        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            using var ec = new ECDsaPkcs11(key);
            using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));

            byte[] signature = ec.SignData(Empty, HashAlgorithmName.SHA256);
            Assert.True(bcl.VerifyData(Empty, signature, HashAlgorithmName.SHA256));
            Assert.True(ec.VerifyData(Empty, signature, HashAlgorithmName.SHA256));

            byte[] next = ec.SignData(Abc, HashAlgorithmName.SHA256);
            Assert.True(ec.VerifyData(Abc, next, HashAlgorithmName.SHA256));
        }
        finally
        {
            try { key.Destroy(); } catch { /* best-effort cleanup */ }
        }
    }

    // GMAC-style use: no plaintext, only associated data. The BCL computes the reference tag from the same key.
    internal static void Assert_AesGcm_EmptyPlaintext_WithAad_MatchesBcl_SessionReusable(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_GCM);
        byte[] rawKey = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] aad = Encoding.ASCII.GetBytes("associated data only");

        byte[] expectedTag = new byte[16];
        using (var reference = new AesGcm(rawKey, 16))
            reference.Encrypt(nonce, Empty, Empty, expectedTag, aad);

        using var session = backend.OpenSession();
        string label = $"empty-gcm-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(rawKey).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = session.ImportKey(tpl);
            using var gcm = new AesGcmPkcs11(key, 16);

            byte[] tag = new byte[16];
            gcm.Encrypt(nonce, Empty, Empty, tag, aad);
            Assert.Equal(expectedTag, tag);
            gcm.Decrypt(nonce, Empty, tag, Empty, aad);

            byte[] nonce2 = RandomNumberGenerator.GetBytes(12);
            byte[] ciphertext = new byte[Abc.Length];
            gcm.Encrypt(nonce2, Abc, ciphertext, tag, aad);
            byte[] roundTripped = new byte[Abc.Length];
            gcm.Decrypt(nonce2, ciphertext, tag, roundTripped, aad);
            Assert.Equal(Abc, roundTripped);
        }
        finally { DestroyByLabel(session, label); }
    }
}
