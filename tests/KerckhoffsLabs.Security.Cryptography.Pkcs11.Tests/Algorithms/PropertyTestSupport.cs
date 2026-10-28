using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using BclECCurve = System.Security.Cryptography.ECCurve;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// What the property-based tests of the <c>Algorithms</c> adapters share: the hashes, curves and
/// parameter sets their theories run over, the capability gates that run before a property, and the
/// keys a property works with. <see cref="BclDifferentialTestCases"/> (CsCheck, the BCL as oracle) and
/// <see cref="AlgorithmLawTestCases"/> (FsCheck, laws without an oracle) both build on it.
/// </summary>
internal static class PropertyTestSupport
{
    // === Hashes ============================================================================

    internal sealed record HashSpec(
        string Name, CKM Digest, CKM Hmac, int Size, int BlockSize,
        Func<bool> HostSupportsHash, Func<bool> HostSupportsHmac,
        Func<byte[], byte[]> Hash, Func<byte[], byte[], byte[]> HashHmac, Func<Pkcs11Session, HashAlgorithm> Create);

    internal static HashSpec Hash(string name) => name switch
    {
        "SHA256" => new(name, CKM.CKM_SHA256, CKM.CKM_SHA256_HMAC, 32, 64,
            () => true, () => true, SHA256.HashData, HMACSHA256.HashData, s => new SHA256Pkcs11(s)),
        "SHA384" => new(name, CKM.CKM_SHA384, CKM.CKM_SHA384_HMAC, 48, 128,
            () => true, () => true, SHA384.HashData, HMACSHA384.HashData, s => new SHA384Pkcs11(s)),
        "SHA512" => new(name, CKM.CKM_SHA512, CKM.CKM_SHA512_HMAC, 64, 128,
            () => true, () => true, SHA512.HashData, HMACSHA512.HashData, s => new SHA512Pkcs11(s)),
        "SHA3-256" => new(name, CKM.CKM_SHA3_256, CKM.CKM_SHA3_256_HMAC, 32, 136,
            () => SHA3_256.IsSupported, () => HMACSHA3_256.IsSupported, SHA3_256.HashData, HMACSHA3_256.HashData, s => new SHA3_256Pkcs11(s)),
        "SHA3-384" => new(name, CKM.CKM_SHA3_384, CKM.CKM_SHA3_384_HMAC, 48, 104,
            () => SHA3_384.IsSupported, () => HMACSHA3_384.IsSupported, SHA3_384.HashData, HMACSHA3_384.HashData, s => new SHA3_384Pkcs11(s)),
        "SHA3-512" => new(name, CKM.CKM_SHA3_512, CKM.CKM_SHA3_512_HMAC, 64, 72,
            () => SHA3_512.IsSupported, () => HMACSHA3_512.IsSupported, SHA3_512.HashData, HMACSHA3_512.HashData, s => new SHA3_512Pkcs11(s)),
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, "Unexpected hash."),
    };

    /// <summary>The hashes the default policy allows for a digest or an HMAC.</summary>
    public static TheoryData<string> Hashes => new(HashNames);

    internal static readonly string[] HashNames = ["SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512"];

    /// <summary>The PRF hashes of the KDFs whose adapters take SHA-2 only.</summary>
    public static TheoryData<string> Sha2Hashes => ["SHA256", "SHA384", "SHA512"];

    // === RSA ===============================================================================

    /// <summary>The RSA signature schemes by padding and hash.</summary>
    public static TheoryData<string, string> RsaSignatureSchemes
    {
        get
        {
            var data = new TheoryData<string, string>();
            foreach (string padding in new[] { "Pkcs1", "Pss" })
                foreach (string hash in HashNames)
                    data.Add(padding, hash);
            return data;
        }
    }

    internal static RSASignaturePadding SignaturePadding(string padding) =>
        padding == "Pss" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

    // The combined mechanism SignData uses: the token hashes and signs in one C_Sign.
    internal static CKM RsaSignMechanism(string hashName, string padding) => (hashName, padding) switch
    {
        ("SHA256", "Pkcs1") => CKM.CKM_SHA256_RSA_PKCS,
        ("SHA384", "Pkcs1") => CKM.CKM_SHA384_RSA_PKCS,
        ("SHA512", "Pkcs1") => CKM.CKM_SHA512_RSA_PKCS,
        ("SHA3-256", "Pkcs1") => CKM.CKM_SHA3_256_RSA_PKCS,
        ("SHA3-384", "Pkcs1") => CKM.CKM_SHA3_384_RSA_PKCS,
        ("SHA3-512", "Pkcs1") => CKM.CKM_SHA3_512_RSA_PKCS,
        ("SHA256", "Pss") => CKM.CKM_SHA256_RSA_PKCS_PSS,
        ("SHA384", "Pss") => CKM.CKM_SHA384_RSA_PKCS_PSS,
        ("SHA512", "Pss") => CKM.CKM_SHA512_RSA_PKCS_PSS,
        ("SHA3-256", "Pss") => CKM.CKM_SHA3_256_RSA_PKCS_PSS,
        ("SHA3-384", "Pss") => CKM.CKM_SHA3_384_RSA_PKCS_PSS,
        ("SHA3-512", "Pss") => CKM.CKM_SHA3_512_RSA_PKCS_PSS,
        _ => throw new ArgumentOutOfRangeException(nameof(hashName), $"{padding} over {hashName}", "Unexpected RSA signature scheme."),
    };

    // A token that lists OAEP may still refuse a hash in its parameters (SoftHSM 2.5 takes SHA-1 only),
    // which it reports on the first operation; that is a capability, so it skips before the property.
    internal static void RequireOaepHash(Func<byte[]> probe)
    {
        try
        {
            probe();
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue is
            CKR.CKR_MECHANISM_PARAM_INVALID or CKR.CKR_MECHANISM_INVALID or CKR.CKR_ARGUMENTS_BAD or CKR.CKR_FUNCTION_NOT_SUPPORTED)
        {
            Assert.Skip($"Token advertises OAEP but refuses this hash ({ex.ReturnValue}).");
        }
    }

    // The longest message OAEP takes under a 2048-bit key and the hash.
    internal static int OaepMaxLength(RSAPkcs11 rsa, string hashName) => (rsa.KeySize / 8) - (2 * Hash(hashName).Size) - 2;

    // Generates a 2048-bit RSA key pair (private half CKA_SIGN and CKA_DECRYPT, public half CKA_VERIFY and
    // CKA_ENCRYPT), runs body with it and destroys it.
    internal static void WithRsa(IPkcs11Backend backend, Action<RSAPkcs11> body)
    {
        using var session = backend.OpenSession();
        string label = $"prop-rsa-{Guid.NewGuid():N}";
        byte[] id = TestKeys.IdFor(label);
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().Encrypt().ModulusBits(2048).PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Decrypt().Build();
        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            using var rsa = new RSAPkcs11(key);
            body(rsa);
        }
        finally
        {
            try { key.Destroy(); } catch (Pkcs11Exception) { /* best-effort cleanup */ }
        }
    }

    // === EC ================================================================================

    /// <summary>The NIST curves.</summary>
    public static TheoryData<string> Curves => new(CurveNames);

    private static readonly string[] CurveNames = ["P-256", "P-384", "P-521"];

    /// <summary>The NIST curves by ECDSA signature encoding.</summary>
    public static TheoryData<string, DSASignatureFormat> CurvesAndSignatureFormats
    {
        get
        {
            var data = new TheoryData<string, DSASignatureFormat>();
            foreach (string curve in CurveNames)
                foreach (DSASignatureFormat format in new[] { DSASignatureFormat.IeeeP1363FixedFieldConcatenation, DSASignatureFormat.Rfc3279DerSequence })
                    data.Add(curve, format);
            return data;
        }
    }

    internal static (BclECCurve Curve, HashAlgorithmName Hash) EcSpec(string curve) => curve switch
    {
        "P-256" => (BclECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256),
        "P-384" => (BclECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384),
        "P-521" => (BclECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512),
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unknown EC curve."),
    };

    // Generates an EC key pair on the curve, private half CKA_SIGN (public CKA_VERIFY) or CKA_DERIVE, and
    // runs body with it. A token that does not generate keys on the curve skips.
    internal static void WithEcKey(IPkcs11Backend backend, Pkcs11Session session, string curve, bool derive, Action<Pkcs11Key> body)
    {
        string label = $"prop-ec-{Guid.NewGuid():N}";
        byte[] id = TestKeys.IdFor(label);
        var pub = ObjectTemplate.ForPublicKey(CKK.CKK_EC).Label(label).Id(id).EcParams(TestKeys.EcParams(curve));
        var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Label(label).Id(id);
        using var pubTpl = (derive ? pub : pub.Verify()).Build();
        using var privTpl = (derive ? priv.Derive() : priv.Sign()).Build();

        Pkcs11Key key;
        try
        {
            key = session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTpl, privTpl);
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue is CKR.CKR_CURVE_NOT_SUPPORTED or CKR.CKR_DOMAIN_PARAMS_INVALID)
        {
            Assert.Skip($"The token does not generate keys on {curve} ({ex.ReturnValue}).");
            throw; // unreachable: Assert.Skip throws
        }

        using (key)
        {
            try
            {
                body(key);
            }
            finally
            {
                try { key.Destroy(); } catch (Pkcs11Exception) { /* best-effort cleanup */ }
            }
        }
    }

    // === Post-quantum ======================================================================

    /// <summary>The ML-DSA parameter sets.</summary>
    public static TheoryData<CkpMlDsa> MlDsaParameterSets => [CkpMlDsa.CKP_ML_DSA_44, CkpMlDsa.CKP_ML_DSA_65, CkpMlDsa.CKP_ML_DSA_87];

    /// <summary>The ML-KEM parameter sets.</summary>
    public static TheoryData<CkpMlKem> MlKemParameterSets => [CkpMlKem.CKP_ML_KEM_512, CkpMlKem.CKP_ML_KEM_768, CkpMlKem.CKP_ML_KEM_1024];

    // Generates a post-quantum key pair of the type and parameter set, private half CKA_SIGN (public
    // CKA_VERIFY) or, for ML-KEM, CKA_DECAPSULATE (public CKA_ENCAPSULATE), runs body with it and destroys it.
    internal static void WithPqcKey(IPkcs11Backend backend, CKK keyType, CKM keyGen, ulong parameterSet, Action<Pkcs11Session, Pkcs11Key> body)
    {
        using var session = backend.OpenSession();
        string label = $"prop-pqc-{Guid.NewGuid():N}";
        byte[] id = TestKeys.IdFor(label);
        bool kem = keyType == CKK.CKK_ML_KEM;
        var pub = ObjectTemplate.ForPublicKey(keyType).Label(label).Id(id).Attribute(CKA.CKA_PARAMETER_SET, parameterSet);
        var priv = ObjectTemplate.ForPrivateKey(keyType).Label(label).Id(id);
        using var pubTpl = (kem ? pub.Attribute(CKA.CKA_ENCAPSULATE, true) : pub.Verify()).Build();
        using var privTpl = (kem ? priv.Attribute(CKA.CKA_DECAPSULATE, true) : priv.Sign()).Build();
        using var key = session.GenerateKeyPair(new Mechanism(keyGen), pubTpl, privTpl);
        try
        {
            body(session, key);
        }
        finally
        {
            try { key.Destroy(); } catch (Pkcs11Exception) { /* best-effort cleanup */ }
        }
    }

    // === Secret keys =======================================================================

    // Imports value as a secret key of the type, with the usages configure adds, runs body with it and
    // destroys it.
    internal static void WithSecretKey(
        IPkcs11Backend backend, Pkcs11Session session, CKK keyType, byte[] value,
        Func<SecretKeyTemplateBuilder, SecretKeyTemplateBuilder> configure, Action<Pkcs11Key> body)
    {
        using var template = configure(ObjectTemplate.ForSecretKey(keyType)
            .Label($"prop-{Guid.NewGuid():N}").Value(value).OnToken(backend.SupportsTokenObjects)).Build();
        using var key = session.ImportKey(template);
        try
        {
            body(key);
        }
        finally
        {
            try { key.Destroy(); } catch (Pkcs11Exception) { /* best-effort cleanup */ }
        }
    }

    // === Gates =============================================================================

    internal static void RequireHost(bool supported, string reason) => Assert.SkipUnless(supported, reason);

    // Whether size is one of the sizes the KeySizes describes.
    internal static bool IsLegal(int size, KeySizes sizes) =>
        size >= sizes.MinSize && size <= sizes.MaxSize &&
        (sizes.SkipSize == 0 ? size == sizes.MinSize : (size - sizes.MinSize) % sizes.SkipSize == 0);
}
