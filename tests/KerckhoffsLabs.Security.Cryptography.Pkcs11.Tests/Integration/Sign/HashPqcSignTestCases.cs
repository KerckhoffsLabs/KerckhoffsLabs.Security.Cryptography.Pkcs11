using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Backend-agnostic tests of pre-hash PQC signing (PKCS#11 v3.2): HashSLH-DSA, and the bare
/// <c>CKM_HASH_ML_DSA</c> / <c>CKM_HASH_SLH_DSA</c> mechanisms with <see cref="CkmHashPqcSignParams"/>.
/// </summary>
/// <remarks>
/// A combined mechanism such as <c>CKM_HASH_SLH_DSA_SHA256</c> hashes the message itself. The bare
/// mechanism takes the digest the caller computed and names its hash in <see cref="CkmHashPqcSignParams"/>.
/// Both produce the same HashSLH-DSA / HashML-DSA signature over the message, so a signature made one way
/// must verify the other way. That cross-check fails if the library marshals the hash field wrongly.
/// </remarks>
internal static class HashPqcSignTestCases
{
    private static readonly byte[] Message = "pre-hash PQC signing, checked both ways"u8.ToArray();

    internal static void Assert_HashSlhDsaSha256_SignsAndVerifies(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKM.CKM_HASH_SLH_DSA_SHA256);
        WithKeyPair(backend, CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, key =>
        {
            var mechanism = new Mechanism(CKM.CKM_HASH_SLH_DSA_SHA256, new CkmPqcSignParams());

            byte[] signature = key.Sign(mechanism, Message);

            Assert.True(key.Verify(mechanism, Message, signature));
            Assert.False(key.Verify(mechanism, Tampered(Message), signature));
        });
    }

    internal static void Assert_HashSlhDsa_ExplicitHash_AgreesWithCombined(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKM.CKM_HASH_SLH_DSA, CKM.CKM_HASH_SLH_DSA_SHA256);
        WithKeyPair(backend, CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128F,
            key => AssertExplicitHashAgreesWithCombined(key, CKM.CKM_HASH_SLH_DSA, CKM.CKM_HASH_SLH_DSA_SHA256));
    }

    internal static void Assert_HashMlDsa_ExplicitHash_AgreesWithCombined(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_HASH_ML_DSA, CKM.CKM_HASH_ML_DSA_SHA256);
        WithKeyPair(backend, CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKK.CKK_ML_DSA, (ulong)CkpMlDsa.CKP_ML_DSA_65,
            key => AssertExplicitHashAgreesWithCombined(key, CKM.CKM_HASH_ML_DSA, CKM.CKM_HASH_ML_DSA_SHA256));
    }

    private static void AssertExplicitHashAgreesWithCombined(Pkcs11Key key, CKM bare, CKM combinedSha256)
    {
        var explicitHash = new Mechanism(bare, new CkmHashPqcSignParams(CKM.CKM_SHA256));
        var combined = new Mechanism(combinedSha256, new CkmPqcSignParams());
        byte[] digest = SHA256.HashData(Message);

        byte[] overDigest = key.Sign(explicitHash, digest);
        Assert.True(key.Verify(combined, Message, overDigest), "a signature over SHA-256(m) with the hash named should verify as the combined mechanism over m");
        Assert.False(key.Verify(combined, Tampered(Message), overDigest));

        byte[] overMessage = key.Sign(combined, Message);
        Assert.True(key.Verify(explicitHash, digest, overMessage), "a combined-mechanism signature should verify over the digest with the hash named");
    }

    private static void WithKeyPair(IPkcs11Backend backend, CKM generation, CKK keyType, ulong parameterSet, Action<Pkcs11Key> body)
    {
        using var session = backend.OpenSession();
        string label = $"kl-hashpqc-{Guid.NewGuid():N}";
        byte[] id = System.Text.Encoding.ASCII.GetBytes(label);
        using var publicTemplate = ObjectTemplate.ForPublicKey(keyType)
            .Label(label).Id(id).Verify().Attribute(CKA.CKA_PARAMETER_SET, parameterSet).Build();
        using var privateTemplate = ObjectTemplate.ForPrivateKey(keyType).Label(label).Id(id).Sign().Build();
        using var key = session.GenerateKeyPair(new Mechanism(generation), publicTemplate, privateTemplate);
        try { body(key); }
        finally { key.Destroy(); }
    }

    private static byte[] Tampered(byte[] data)
    {
        byte[] copy = [.. data];
        copy[0] ^= 0x01;
        return copy;
    }
}
