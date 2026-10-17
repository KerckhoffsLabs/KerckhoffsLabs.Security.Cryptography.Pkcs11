using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Drives <see cref="Pkcs11MechanismMap.MlDsaHashSign"/> (<c>CKM_HASH_ML_DSA_SHA256</c>, PKCS#11 v3.2)
/// against a real token, feeding it the raw message rather than a pre-computed hash: a combined-hash
/// mechanism digests its input itself. BouncyHsm (BouncyCastle) is an implementation independent of
/// the opencryptoki one this was first written against, so it is a second oracle for this library's
/// <c>CK_SIGN_ADDITIONAL_CONTEXT</c> marshalling, not just a unit assertion against our own
/// understanding of the layout.
/// </summary>
[Collection("BouncyHsm")]
public sealed class SignHashMlDsaTests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    private void RequireHashMlDsa()
    {
        if (!_backend.Supports(CKM.CKM_ML_DSA_KEY_PAIR_GEN))
            Assert.Skip("BouncyHsm: CKM_ML_DSA_KEY_PAIR_GEN not available (needs OpenSSL 3.5).");
        if (!_backend.Supports(CKM.CKM_HASH_ML_DSA_SHA256))
            Assert.Skip("BouncyHsm: CKM_HASH_ML_DSA_SHA256 not advertised by this token.");
    }

    [Fact(SkipUnless = nameof(BouncyHsmBackendFixture.BouncyHsmAvailable), SkipType = typeof(BouncyHsmBackendFixture), Skip = "Requires " + nameof(BouncyHsmBackendFixture.BouncyHsmAvailable))]
    public void HashMlDsaSha256_RoundTrips()
    {
        RequireHashMlDsa();

        using var session = ((IPkcs11Backend)_backend).OpenSession();
        string label = $"hash-mldsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

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
            try { key.Destroy(); } catch { /* best-effort cleanup */ }
        }
    }
}
