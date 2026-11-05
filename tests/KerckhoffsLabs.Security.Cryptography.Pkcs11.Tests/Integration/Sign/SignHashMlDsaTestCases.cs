using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Drives <see cref="Pkcs11MechanismMap.MlDsaHashSign"/> (<c>CKM_HASH_ML_DSA_SHA256</c>, PKCS#11 v3.2)
/// against a real token, feeding it the raw message rather than a pre-computed hash: a combined-hash
/// mechanism digests its input itself. Each token that runs it is an independent oracle for this library's
/// <c>CK_SIGN_ADDITIONAL_CONTEXT</c> marshalling.
/// </summary>
internal static class SignHashMlDsaTestCases
{
    internal static void Assert_HashMlDsaSha256_RoundTrips(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_ML_DSA_KEY_PAIR_GEN))
            Assert.Skip("Backend does not advertise CKM_ML_DSA_KEY_PAIR_GEN.");
        if (!backend.Supports(CKM.CKM_HASH_ML_DSA_SHA256))
            Assert.Skip("Backend does not advertise CKM_HASH_ML_DSA_SHA256.");

        using var session = backend.OpenSession();
        string label = $"hash-mldsa-{Guid.NewGuid():N}";
        byte[] id = Guid.NewGuid().ToByteArray(); // 16 bytes: FreeHSM takes a CKA_ID of at most 32

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA)
            .Label(label).Id(id).Verify()
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlDsa.CKP_ML_DSA_65).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA)
            .Label(label).Id(id).Sign().Build();

        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            byte[] data = Encoding.UTF8.GetBytes("HashML-DSA over CKM_HASH_ML_DSA_SHA256, raw message");

            byte[] signature = key.Sign(Pkcs11MechanismMap.MlDsaHashSign(HashAlgorithmName.SHA256), data);
            Assert.NotEmpty(signature);

            Assert.True(key.Verify(Pkcs11MechanismMap.MlDsaHashSign(HashAlgorithmName.SHA256), data, signature));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(key.Verify(Pkcs11MechanismMap.MlDsaHashSign(HashAlgorithmName.SHA256), tampered, signature));
        }
        finally
        {
            try { key.Destroy(); } catch (Pkcs11Exception) { /* best-effort cleanup */ }
        }
    }
}
