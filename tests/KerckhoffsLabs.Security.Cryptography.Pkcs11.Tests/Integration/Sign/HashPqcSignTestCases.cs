using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Backend-agnostic tests of pre-hash PQC signing (PKCS#11 v3.2): every combined HashML-DSA / HashSLH-DSA
/// mechanism, and the bare <c>CKM_HASH_ML_DSA</c> / <c>CKM_HASH_SLH_DSA</c> mechanisms with
/// <see cref="CkmHashPqcSignParams"/>.
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

    // The Recommended policy refuses the 224-bit hashes (no benefit over SHA-256): the 224-bit combined
    // mechanisms, the digests, and the bare mechanism naming one (a parameter check). These cases test the
    // token's conformance, not our policy, so the 224-bit rows alone run under Recommended with exactly those
    // re-admitted; every other row runs under the session's default. The refusals are pinned in Unit/Policy.
    private static readonly ComposedCryptoPolicy RecommendedPlus224 = CryptoPolicy.Recommended
        .ToBuilder("Recommended + 224-bit HashML-DSA / HashSLH-DSA (conformance tests)")
        .RemoveMechanism(CKM.CKM_HASH_ML_DSA) // drops its >= 256-bit pre-hash parameter check
        .RemoveMechanism(CKM.CKM_HASH_SLH_DSA)
        .AllowMechanism(CKM.CKM_HASH_ML_DSA, [CryptoOperation.Sign, CryptoOperation.Verify], "Token conformance test.")
        .AllowMechanism(CKM.CKM_HASH_SLH_DSA, [CryptoOperation.Sign, CryptoOperation.Verify], "Token conformance test.")
        .AllowMechanism(CKM.CKM_HASH_ML_DSA_SHA224, [CryptoOperation.Sign, CryptoOperation.Verify], "Token conformance test.")
        .AllowMechanism(CKM.CKM_HASH_ML_DSA_SHA3_224, [CryptoOperation.Sign, CryptoOperation.Verify], "Token conformance test.")
        .AllowMechanism(CKM.CKM_HASH_SLH_DSA_SHA224, [CryptoOperation.Sign, CryptoOperation.Verify], "Token conformance test.")
        .AllowMechanism(CKM.CKM_HASH_SLH_DSA_SHA3_224, [CryptoOperation.Sign, CryptoOperation.Verify], "Token conformance test.")
        .AllowMechanism(CKM.CKM_SHA224, [CryptoOperation.Digest], "Token conformance test.")
        .AllowMechanism(CKM.CKM_SHA3_224, [CryptoOperation.Digest], "Token conformance test.")
        .Build();

    private static IDisposable? Admit224(Pkcs11Session session, CKM combined) =>
        combined is CKM.CKM_HASH_ML_DSA_SHA224 or CKM.CKM_HASH_ML_DSA_SHA3_224
            or CKM.CKM_HASH_SLH_DSA_SHA224 or CKM.CKM_HASH_SLH_DSA_SHA3_224
            ? session.UsePolicy(RecommendedPlus224)
            : null;

    /// <summary>Every combined <c>CKM_HASH_ML_DSA_&lt;H&gt;</c> mechanism in PKCS#11 v3.2.</summary>
    public static TheoryData<CKM> CombinedHashMlDsaMechanisms =>
    [
        CKM.CKM_HASH_ML_DSA_SHA224,
        CKM.CKM_HASH_ML_DSA_SHA256,
        CKM.CKM_HASH_ML_DSA_SHA384,
        CKM.CKM_HASH_ML_DSA_SHA512,
        CKM.CKM_HASH_ML_DSA_SHA3_224,
        CKM.CKM_HASH_ML_DSA_SHA3_256,
        CKM.CKM_HASH_ML_DSA_SHA3_384,
        CKM.CKM_HASH_ML_DSA_SHA3_512,
        CKM.CKM_HASH_ML_DSA_SHAKE128,
        CKM.CKM_HASH_ML_DSA_SHAKE256,
    ];

    /// <summary>Every combined <c>CKM_HASH_SLH_DSA_&lt;H&gt;</c> mechanism in PKCS#11 v3.2.</summary>
    public static TheoryData<CKM> CombinedHashSlhDsaMechanisms =>
    [
        CKM.CKM_HASH_SLH_DSA_SHA224,
        CKM.CKM_HASH_SLH_DSA_SHA256,
        CKM.CKM_HASH_SLH_DSA_SHA384,
        CKM.CKM_HASH_SLH_DSA_SHA512,
        CKM.CKM_HASH_SLH_DSA_SHA3_224,
        CKM.CKM_HASH_SLH_DSA_SHA3_256,
        CKM.CKM_HASH_SLH_DSA_SHA3_384,
        CKM.CKM_HASH_SLH_DSA_SHA3_512,
        CKM.CKM_HASH_SLH_DSA_SHAKE128,
        CKM.CKM_HASH_SLH_DSA_SHAKE256,
    ];

    // (hash named in CkmHashPqcSignParams, the matching combined mechanism) for the bare-mechanism
    // cross-check. The SHAKE variants are left out: PKCS#11 v3.2 defines no plain SHAKE digest mechanism to
    // name in the hash field (CKM_SHAKE_*_KEY_DERIVATION are key derivations), so the bare form has no SHAKE
    // counterpart to check. The combined SHAKE mechanisms are covered by the SignsAndVerifies theories.

    /// <summary>(hash, combined) pairs for the bare <c>CKM_HASH_ML_DSA</c> cross-check.</summary>
    public static TheoryData<CKM, CKM> ExplicitHashMlDsaPairs => new()
    {
        { CKM.CKM_SHA224, CKM.CKM_HASH_ML_DSA_SHA224 },
        { CKM.CKM_SHA256, CKM.CKM_HASH_ML_DSA_SHA256 },
        { CKM.CKM_SHA384, CKM.CKM_HASH_ML_DSA_SHA384 },
        { CKM.CKM_SHA512, CKM.CKM_HASH_ML_DSA_SHA512 },
        { CKM.CKM_SHA3_224, CKM.CKM_HASH_ML_DSA_SHA3_224 },
        { CKM.CKM_SHA3_256, CKM.CKM_HASH_ML_DSA_SHA3_256 },
        { CKM.CKM_SHA3_384, CKM.CKM_HASH_ML_DSA_SHA3_384 },
        { CKM.CKM_SHA3_512, CKM.CKM_HASH_ML_DSA_SHA3_512 },
    };

    /// <summary>(hash, combined) pairs for the bare <c>CKM_HASH_SLH_DSA</c> cross-check.</summary>
    public static TheoryData<CKM, CKM> ExplicitHashSlhDsaPairs => new()
    {
        { CKM.CKM_SHA224, CKM.CKM_HASH_SLH_DSA_SHA224 },
        { CKM.CKM_SHA256, CKM.CKM_HASH_SLH_DSA_SHA256 },
        { CKM.CKM_SHA384, CKM.CKM_HASH_SLH_DSA_SHA384 },
        { CKM.CKM_SHA512, CKM.CKM_HASH_SLH_DSA_SHA512 },
        { CKM.CKM_SHA3_224, CKM.CKM_HASH_SLH_DSA_SHA3_224 },
        { CKM.CKM_SHA3_256, CKM.CKM_HASH_SLH_DSA_SHA3_256 },
        { CKM.CKM_SHA3_384, CKM.CKM_HASH_SLH_DSA_SHA3_384 },
        { CKM.CKM_SHA3_512, CKM.CKM_HASH_SLH_DSA_SHA3_512 },
    };

    private static readonly PqcFamily MlDsa = new(CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKK.CKK_ML_DSA, (ulong)CkpMlDsa.CKP_ML_DSA_65, CKM.CKM_HASH_ML_DSA);
    private static readonly PqcFamily SlhDsa = new(CKM.CKM_SLH_DSA_KEY_PAIR_GEN, CKK.CKK_SLH_DSA, (ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, CKM.CKM_HASH_SLH_DSA);

    internal static void Assert_HashMlDsa_SignsAndVerifies(IPkcs11Backend backend, CKM combined) =>
        AssertSignsAndVerifies(backend, MlDsa, combined);

    internal static void Assert_HashSlhDsa_SignsAndVerifies(IPkcs11Backend backend, CKM combined) =>
        AssertSignsAndVerifies(backend, SlhDsa, combined);

    internal static void Assert_HashMlDsa_ExplicitHash_AgreesWithCombined(IPkcs11Backend backend, CKM hash, CKM combined) =>
        AssertExplicitHashAgreesWithCombined(backend, MlDsa, hash, combined);

    internal static void Assert_HashSlhDsa_ExplicitHash_AgreesWithCombined(IPkcs11Backend backend, CKM hash, CKM combined) =>
        AssertExplicitHashAgreesWithCombined(backend, SlhDsa, hash, combined);

    private static void AssertSignsAndVerifies(IPkcs11Backend backend, PqcFamily family, CKM combined)
    {
        backend.RequireMechanisms(family.Generation, combined);
        WithKeyPair(backend, family, (session, key) =>
        {
            using var policy = Admit224(session, combined);
            var mechanism = new Mechanism(combined, new CkmPqcSignParams());

            byte[] signature = key.Sign(mechanism, Message);

            Assert.True(key.Verify(mechanism, Message, signature));
            Assert.False(key.Verify(mechanism, Tampered(Message), signature));
        });
    }

    private static void AssertExplicitHashAgreesWithCombined(IPkcs11Backend backend, PqcFamily family, CKM hash, CKM combined)
    {
        backend.RequireMechanisms(family.Generation, family.Bare, combined);
        WithKeyPair(backend, family, (session, key) =>
        {
            using var policy = Admit224(session, combined);
            AssertExplicitHashAgreesWithCombined(key, family.Bare, hash, combined, DigestOf(backend, session, hash));
        });
    }

    private static void AssertExplicitHashAgreesWithCombined(Pkcs11Key key, CKM bare, CKM hash, CKM combined, byte[] digest)
    {
        var explicitHash = new Mechanism(bare, new CkmHashPqcSignParams(hash));
        var combinedMechanism = new Mechanism(combined, new CkmPqcSignParams());

        byte[] overDigest = key.Sign(explicitHash, digest);
        Assert.True(key.Verify(combinedMechanism, Message, overDigest), $"a signature over {hash}(m) with the hash named should verify as {combined} over m");
        Assert.False(key.Verify(combinedMechanism, Tampered(Message), overDigest));

        byte[] overMessage = key.Sign(combinedMechanism, Message);
        Assert.True(key.Verify(explicitHash, digest, overMessage), $"a {combined} signature should verify over the {hash} digest with the hash named");
    }

    // The digest the caller hands the bare mechanism. Computed off-token with the BCL where it has the hash,
    // so the cross-check does not lean on the token twice; SHA-224 and SHA3-224 have no BCL implementation,
    // and SHA-3 needs OS support, so those fall back to the token's own C_Digest (skipping if it lacks it).
    private static byte[] DigestOf(IPkcs11Backend backend, Pkcs11Session session, CKM hash)
    {
        byte[]? bcl = hash switch
        {
            CKM.CKM_SHA256 => SHA256.HashData(Message),
            CKM.CKM_SHA384 => SHA384.HashData(Message),
            CKM.CKM_SHA512 => SHA512.HashData(Message),
            CKM.CKM_SHA3_256 when SHA3_256.IsSupported => SHA3_256.HashData(Message),
            CKM.CKM_SHA3_384 when SHA3_384.IsSupported => SHA3_384.HashData(Message),
            CKM.CKM_SHA3_512 when SHA3_512.IsSupported => SHA3_512.HashData(Message),
            _ => null,
        };
        if (bcl is not null)
            return bcl;

        backend.RequireMechanism(hash);
        return session.Digest(new Mechanism(hash), Message);
    }

    private static void WithKeyPair(IPkcs11Backend backend, PqcFamily family, Action<Pkcs11Session, Pkcs11Key> body)
    {
        (CKM generation, CKK keyType, ulong parameterSet, _) = family;
        using var session = backend.OpenSession();
        string label = $"kl-hashpqc-{Guid.NewGuid():N}";
        byte[] id = TestKeys.IdFor(label);
        using var publicTemplate = ObjectTemplate.ForPublicKey(keyType)
            .Label(label).Id(id).Verify().Attribute(CKA.CKA_PARAMETER_SET, parameterSet).Build();
        using var privateTemplate = ObjectTemplate.ForPrivateKey(keyType).Label(label).Id(id).Sign().Build();
        using var key = session.GenerateKeyPair(new Mechanism(generation), publicTemplate, privateTemplate);
        try { body(session, key); }
        finally { key.Destroy(); }
    }

    private static byte[] Tampered(byte[] data)
    {
        byte[] copy = [.. data];
        copy[0] ^= 0x01;
        return copy;
    }

    /// <summary>A signature family: its key-pair generation, key type, the parameter set the tests use, and its bare pre-hash mechanism.</summary>
    private sealed record PqcFamily(CKM Generation, CKK KeyType, ulong ParameterSet, CKM Bare);
}
