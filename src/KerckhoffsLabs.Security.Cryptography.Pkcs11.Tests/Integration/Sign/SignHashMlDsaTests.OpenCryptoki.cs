using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Drives <see cref="Pkcs11MechanismMap.MlDsaHashSign"/> (<c>CKM_HASH_ML_DSA_SHA256</c>, PKCS#11 v3.2)
/// against a real token, feeding it the raw message rather than a pre-computed hash — opencryptoki's
/// <c>ml_dsa_hash_sign</c> digests the input itself for every combined-hash mechanism except the bare
/// <c>CKM_HASH_ML_DSA</c> (verified against <c>vendor/opencryptoki/usr/lib/common/mech_pqc.c</c>,
/// which only treats the input as an already-hashed digest for that one mechanism). The same file's
/// <c>ml_dsa_get_digest_mech</c> validates <c>ulParameterLen</c> against
/// <c>sizeof(CK_SIGN_ADDITIONAL_CONTEXT)</c> for every combined mechanism (deriving the hash from the
/// mechanism type itself, not from a params field), so a malformed block cannot pass silently — a
/// real oracle for this library's marshalling, not just a unit assertion against our own
/// understanding of the layout.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class SignHashMlDsaTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    private void RequireHashMlDsa()
    {
        if (!_backend.Supports(CKM.CKM_ML_DSA_KEY_PAIR_GEN))
            Assert.Skip("opencryptoki: CKM_ML_DSA_KEY_PAIR_GEN not available (needs OpenSSL 3.5).");
        if (!_backend.Supports(CKM.CKM_HASH_ML_DSA_SHA256))
            Assert.Skip("opencryptoki: CKM_HASH_ML_DSA_SHA256 not advertised by this token.");
    }

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void HashMlDsaSha256_RoundTrips()
    {
        RequireHashMlDsa();

        using var workspace = ((IPkcs11Backend)_backend).OpenWorkspace();
        string label = $"hash-mldsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA)
            .Label(label).Id(id).Verify()
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlDsa.CKP_ML_DSA_65).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA)
            .Label(label).Id(id).Sign().Build();

        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), privTpl, pubTpl);
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
