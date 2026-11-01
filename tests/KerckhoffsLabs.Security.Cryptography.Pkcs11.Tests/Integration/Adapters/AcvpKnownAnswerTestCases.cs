using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Vectors;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>
/// Known-answer tests for ML-KEM (FIPS 203) and ML-DSA (FIPS 204) from NIST's ACVP-Server vectors (see
/// <see cref="AcvpVectors"/>): each case imports the published key and checks the published answer, so a token or a
/// marshalling bug that a round trip or a BCL cross-check would share cannot pass. Each case is named by its ACVP tcId.
/// </summary>
/// <remarks>
/// The cases import private keys from their FIPS 203 / 204 expanded encoding (<c>CKA_VALUE</c>) and run under
/// AllowInsecure: they read a shared secret back, and some use 224-bit pre-hashes, which Recommended refuses.
/// <c>notTakenBecause</c> declares a backend that refuses a key or a mechanism as something it does not take, as in
/// <see cref="Mechanisms.AlgorithmConformanceTestCases"/>: the case then skips with that reason, an undeclared refusal
/// fails, and a declared one that no longer happens fails so the declaration goes. A case with a context skips on a
/// backend that declares it takes none (<see cref="IPkcs11Backend.SupportsPqcSignContext"/>); the empty-context cases
/// cover it.
/// </remarks>
internal static class AcvpKnownAnswerTestCases
{
    private static readonly CKR[] NotTaken =
    [
        CKR.CKR_ATTRIBUTE_VALUE_INVALID, CKR.CKR_ATTRIBUTE_TYPE_INVALID, CKR.CKR_TEMPLATE_INCONSISTENT,
        CKR.CKR_TEMPLATE_INCOMPLETE, CKR.CKR_MECHANISM_INVALID, CKR.CKR_MECHANISM_PARAM_INVALID,
        CKR.CKR_KEY_TYPE_INCONSISTENT, CKR.CKR_DOMAIN_PARAMS_INVALID, CKR.CKR_FUNCTION_NOT_SUPPORTED,
    ];

    public static TheoryData<string, int> MlKemDecapsulationCases =>
        [.. AcvpVectors.MlKemDecapsulations.Select(c => (c.ParameterSet, c.TcId))];

    public static TheoryData<string, int> MlDsaPureVerificationCases =>
        [.. AcvpVectors.MlDsaVerifications.Where(c => c.PreHash == "pure").Select(c => (c.ParameterSet, c.TcId))];

    public static TheoryData<string, int> MlDsaPreHashVerificationCases =>
        [.. AcvpVectors.MlDsaVerifications.Where(c => c.PreHash == "preHash").Select(c => (c.ParameterSet, c.TcId))];

    public static TheoryData<string, int> MlDsaDeterministicSignatureCases =>
        [.. AcvpVectors.MlDsaDeterministicSignatures.Select(c => (c.ParameterSet, c.TcId))];

    // ML-KEM.Decaps (FIPS 203 §7.3): ACVP ML-KEM-encapDecap-FIPS203, decapsulation groups. A "valid decapsulation"
    // case recovers the encapsulated K; a "modified ciphertext" case must give the implicit-rejection K, J(z‖c),
    // without an error.
    internal static void Assert_MlKem_Decapsulation_Acvp(IPkcs11Backend backend, string parameterSet, int tcId, string? notTakenBecause = null)
    {
        AcvpVectors.MlKemDecapsulation v = AcvpVectors.MlKemDecapsulations.Single(c => c.TcId == tcId);
        Assert.Equal(parameterSet, v.ParameterSet);
        (CkpMlKem ckp, MLKemAlgorithm algorithm) = parameterSet switch
        {
            "ML-KEM-512" => (CkpMlKem.CKP_ML_KEM_512, MLKemAlgorithm.MLKem512),
            "ML-KEM-768" => (CkpMlKem.CKP_ML_KEM_768, MLKemAlgorithm.MLKem768),
            "ML-KEM-1024" => (CkpMlKem.CKP_ML_KEM_1024, MLKemAlgorithm.MLKem1024),
            _ => throw new ArgumentOutOfRangeException(nameof(parameterSet), parameterSet, null),
        };
        backend.RequireMlKemParameterSet(algorithm.EncapsulationKeySizeInBytes);

        WithSession(backend, session =>
        {
            ObjectHandle priv = Taken(() => ImportPrivateKey(session, CKK.CKK_ML_KEM, (ulong)ckp, v.Dk, CKA.CKA_DECAPSULATE),
                $"an {parameterSet} decapsulation key", notTakenBecause);
            try
            {
                if (notTakenBecause is not null)
                    Assert.Fail($"The backend now takes {parameterSet} keys; drop its notTakenBecause (\"{notTakenBecause}\").");
                ObjectHandle secret = DecapsulateToReadableSecret(session, priv, v.C);
                try
                {
                    using var attrs = session.GetAttributeValue(secret, [CKA.CKA_VALUE]);
                    Assert.Equal(v.K, attrs[0].GetValueAsByteArray());
                }
                finally { session.DestroyObject(secret); }
            }
            finally { session.DestroyObject(priv); }
        });
    }

    // ML-DSA.Verify (FIPS 204 §5.3), pure, with the case's context: ACVP ML-DSA-sigVer-FIPS204, external-interface
    // pure groups. testPassed says whether the published signature must verify.
    internal static void Assert_MlDsa_PureVerification_Acvp(IPkcs11Backend backend, string parameterSet, int tcId, string? notTakenBecause = null)
    {
        AcvpVectors.MlDsaVerification v = AcvpVectors.MlDsaVerifications.Single(c => c.TcId == tcId);
        Assert.Equal(("pure", parameterSet), (v.PreHash, v.ParameterSet));
        backend.RequireMechanism(CKM.CKM_ML_DSA);
        AssertVerifies(backend, v, new Mechanism(CKM.CKM_ML_DSA, new CkmPqcSignParams(context: v.Context)), notTakenBecause);
    }

    // HashML-DSA.Verify (FIPS 204 §5.4), with the case's context: ACVP ML-DSA-sigVer-FIPS204, external-interface
    // preHash groups, through the combined CKM_HASH_ML_DSA_<H> that hashes the message itself.
    internal static void Assert_MlDsa_PreHashVerification_Acvp(IPkcs11Backend backend, string parameterSet, int tcId, string? notTakenBecause = null)
    {
        AcvpVectors.MlDsaVerification v = AcvpVectors.MlDsaVerifications.Single(c => c.TcId == tcId);
        Assert.Equal(("preHash", parameterSet), (v.PreHash, v.ParameterSet));
        CKM combined = HashMlDsa(v.HashAlg);
        backend.RequireMechanism(combined);
        AssertVerifies(backend, v, new Mechanism(combined, new CkmPqcSignParams(context: v.Context)), notTakenBecause);
    }

    // ML-DSA.Sign (FIPS 204 §5.2) in its deterministic variant (rnd = 0^256) with the case's context: ACVP
    // ML-DSA-sigGen-FIPS204, deterministic external pure groups. CKH_DETERMINISTIC_REQUIRED asks the token for that
    // variant, so its signature must be the published one byte for byte; the published signature must also verify
    // under the published public key, which covers a valid signature without a context (ACVP's sigVer has none).
    internal static void Assert_MlDsa_DeterministicSignature_Acvp(IPkcs11Backend backend, string parameterSet, int tcId, string? notTakenBecause = null)
    {
        AcvpVectors.MlDsaSignature v = AcvpVectors.MlDsaDeterministicSignatures.Single(c => c.TcId == tcId);
        Assert.Equal(parameterSet, v.ParameterSet);
        backend.RequireMechanism(CKM.CKM_ML_DSA);
        var mechanism = new Mechanism(CKM.CKM_ML_DSA, new CkmPqcSignParams(CkhHedge.CKH_DETERMINISTIC_REQUIRED, v.Context));
        RequireContextSupport(backend, v.Context);

        WithSession(backend, session =>
        {
            byte[] signature = Taken(() =>
            {
                ObjectHandle priv = ImportPrivateKey(session, CKK.CKK_ML_DSA, (ulong)MlDsaParameterSet(parameterSet), v.Sk, CKA.CKA_SIGN);
                try { return session.Sign(mechanism, priv, v.Message); }
                finally { session.DestroyObject(priv); }
            }, $"deterministic {parameterSet} signing with an imported key", notTakenBecause);
            if (notTakenBecause is not null)
                Assert.Fail($"The backend now signs deterministic {parameterSet}; drop its notTakenBecause (\"{notTakenBecause}\").");
            Assert.True(v.Signature.AsSpan().SequenceEqual(signature),
                $"ACVP tcId {v.TcId}: the {parameterSet} deterministic signature differs from the published one.");

            ObjectHandle pub = ImportPublicKey(session, CKK.CKK_ML_DSA, (ulong)MlDsaParameterSet(parameterSet), v.Pk);
            try { Assert.True(session.Verify(mechanism, pub, v.Message, v.Signature), $"ACVP tcId {v.TcId}: the published signature does not verify."); }
            finally { session.DestroyObject(pub); }
        });
    }

    private static void AssertVerifies(IPkcs11Backend backend, AcvpVectors.MlDsaVerification v, Mechanism mechanism, string? notTakenBecause)
    {
        RequireContextSupport(backend, v.Context);
        WithSession(backend, session =>
        {
            bool verified = Taken(() =>
            {
                ObjectHandle pub = ImportPublicKey(session, CKK.CKK_ML_DSA, (ulong)MlDsaParameterSet(v.ParameterSet), v.Pk);
                try { return session.Verify(mechanism, pub, v.Message, v.Signature); }
                finally { session.DestroyObject(pub); }
            }, $"{v.ParameterSet} verification ({v.PreHash}, {v.HashAlg})", notTakenBecause);
            if (notTakenBecause is not null)
                Assert.Fail($"The backend now verifies {v.ParameterSet} ({v.PreHash}); drop its notTakenBecause (\"{notTakenBecause}\").");
            Assert.True(verified == v.TestPassed,
                $"ACVP tcId {v.TcId} ({v.Reason}): expected the signature to {(v.TestPassed ? "verify" : "be refused")}.");
        });
    }

    // A context is declared per backend: Craton HSM refuses a non-empty one rather than ignore it.
    private static void RequireContextSupport(IPkcs11Backend backend, byte[] context)
    {
        if (context.Length > 0 && !backend.SupportsPqcSignContext)
            Assert.Skip("The backend declares it takes no ML-DSA / SLH-DSA context (IPkcs11Backend.SupportsPqcSignContext).");
    }

    private static CkpMlDsa MlDsaParameterSet(string parameterSet) => parameterSet switch
    {
        "ML-DSA-44" => CkpMlDsa.CKP_ML_DSA_44,
        "ML-DSA-65" => CkpMlDsa.CKP_ML_DSA_65,
        "ML-DSA-87" => CkpMlDsa.CKP_ML_DSA_87,
        _ => throw new ArgumentOutOfRangeException(nameof(parameterSet), parameterSet, null),
    };

    // ACVP hashAlg names to the combined HashML-DSA mechanisms of PKCS#11 v3.2 (the vectors hold only these).
    private static CKM HashMlDsa(string hashAlg) => hashAlg switch
    {
        "SHA2-224" => CKM.CKM_HASH_ML_DSA_SHA224,
        "SHA2-256" => CKM.CKM_HASH_ML_DSA_SHA256,
        "SHA2-384" => CKM.CKM_HASH_ML_DSA_SHA384,
        "SHA2-512" => CKM.CKM_HASH_ML_DSA_SHA512,
        "SHA3-224" => CKM.CKM_HASH_ML_DSA_SHA3_224,
        "SHA3-256" => CKM.CKM_HASH_ML_DSA_SHA3_256,
        "SHA3-384" => CKM.CKM_HASH_ML_DSA_SHA3_384,
        "SHA3-512" => CKM.CKM_HASH_ML_DSA_SHA3_512,
        "SHAKE-128" => CKM.CKM_HASH_ML_DSA_SHAKE128,
        "SHAKE-256" => CKM.CKM_HASH_ML_DSA_SHAKE256,
        _ => throw new ArgumentOutOfRangeException(nameof(hashAlg), hashAlg, null),
    };

    private static ObjectHandle ImportPrivateKey(Pkcs11SessionCore session, CKK keyType, ulong parameterSet, byte[] value, CKA usage)
    {
        using var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var set = new ObjectAttribute(CKA.CKA_PARAMETER_SET, parameterSet);
        using var use = new ObjectAttribute(usage, true);
        using var key = new ObjectAttribute(CKA.CKA_VALUE, value);
        return session.CreateObject([cls, type, token, set, use, key]);
    }

    private static ObjectHandle ImportPublicKey(Pkcs11SessionCore session, CKK keyType, ulong parameterSet, byte[] value)
    {
        using var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var set = new ObjectAttribute(CKA.CKA_PARAMETER_SET, parameterSet);
        using var verify = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var key = new ObjectAttribute(CKA.CKA_VALUE, value);
        return session.CreateObject([cls, type, token, set, verify, key]);
    }

    // Decapsulates into a readable 32-byte generic secret. Decapsulation creates the key with unwrap semantics, where
    // SoftHSM treats CKA_VALUE_LEN as read-only and opencryptoki requires it, so retry without it, as MLKemPkcs11 does.
    private static ObjectHandle DecapsulateToReadableSecret(Pkcs11SessionCore session, ObjectHandle priv, byte[] ciphertext)
    {
        try { return Decapsulate(session, priv, ciphertext, valueLen: true); }
        catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_ATTRIBUTE_READ_ONLY)
        {
            return Decapsulate(session, priv, ciphertext, valueLen: false);
        }
    }

    private static ObjectHandle Decapsulate(Pkcs11SessionCore session, ObjectHandle priv, byte[] ciphertext, bool valueLen)
    {
        using var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var sensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
        using var extractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
        using var length = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
        List<ObjectAttribute> template = valueLen ? [cls, type, token, sensitive, extractable, length] : [cls, type, token, sensitive, extractable];
        return session.DecapsulateKey(new Mechanism(CKM.CKM_ML_KEM), priv, ciphertext, template);
    }

    private static T Taken<T>(Func<T> create, string what, string? notTakenBecause)
    {
        try { return create(); }
        catch (Pkcs11Exception ex) when (NotTaken.Contains(ex.ReturnValue))
        {
            if (notTakenBecause is null)
                Assert.Fail($"The backend refused {what} ({ex.ReturnValue}); if it does not take it, declare that in its test wrapper.");
            Assert.Skip(notTakenBecause);
            throw;
        }
    }

    private static void WithSession(IPkcs11Backend backend, Action<Pkcs11SessionCore> body)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                body(session);
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }
}
