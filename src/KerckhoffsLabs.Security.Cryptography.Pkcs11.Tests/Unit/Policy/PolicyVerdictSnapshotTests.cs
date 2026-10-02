using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

#pragma warning disable KLPKCS11007, KLPKCS11008, KLPKCS11009 // weak curves and mechanisms are part of the snapshot

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>
/// Pins every verdict and reason of the built-in policies against a committed snapshot
/// (<c>Unit/Policy/Snapshots/*.verdicts.tsv</c>), so a change that widens, narrows or rewords
/// <c>Recommended</c> or <c>NistApproved</c> shows up as a reviewed diff rather than silently.
/// </summary>
/// <remarks>
/// <para>
/// The requests cover every <see cref="CKM"/> for every <see cref="CryptoOperation"/> without parameters
/// (condensed to one line per mechanism), the parameter checks (AEAD tag lengths, OAEP, RSA-PSS, the KDF
/// PRFs, raw parameter bytes, ECDH KDFs), hashes, curves, key-agreement KDFs and key types, RSA modulus
/// sizes, key templates and export kinds. Lines are sorted ordinally, so the file is deterministic.
/// </para>
/// <para>
/// Run with <c>UPDATE_POLICY_SNAPSHOTS=1</c> to regenerate the committed files instead of asserting
/// against them. CI never sets it, so there a stale snapshot fails rather than rewriting itself.
/// </para>
/// </remarks>
public sealed class PolicyVerdictSnapshotTests
{
    private const string UpdateEnvironmentVariable = "UPDATE_POLICY_SNAPSHOTS";

    public static TheoryData<string, string> Snapshots => new()
    {
        { "Recommended", "src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Unit/Policy/Snapshots/recommended.verdicts.tsv" },
        { "NistApproved", "src/KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests/Unit/Policy/Snapshots/nist-approved.verdicts.tsv" },
    };

    [Theory]
    [MemberData(nameof(Snapshots))]
    public void Verdicts_MatchTheCommittedSnapshot(string policyName, string relativePath)
    {
        ICryptoPolicy policy = policyName == "Recommended" ? CryptoPolicy.Recommended : CryptoPolicy.NistApproved;
        string path = Path.Join(FindRepoRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar));
        string rendered = Render(policy);
        var utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

        if (Environment.GetEnvironmentVariable(UpdateEnvironmentVariable) == "1")
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, rendered, utf8NoBom);
            return;
        }

        Assert.True(File.Exists(path), $"{relativePath} does not exist; run with {UpdateEnvironmentVariable}=1 to regenerate.");
        string committed = File.ReadAllText(path, utf8NoBom);
        if (committed == rendered)
            return;

        // Name the first differing line, so the failure says what changed.
        string[] expected = committed.Split('\n');
        string[] actual = rendered.Split('\n');
        int i = 0;
        while (i < expected.Length && i < actual.Length && expected[i] == actual[i])
            i++;
        Assert.Fail(
            $"{relativePath} is stale ({policyName} verdicts changed); review the change and run with " +
            $"{UpdateEnvironmentVariable}=1 to regenerate. First difference at line {i + 1}:\n" +
            $"  committed: {(i < expected.Length ? expected[i] : "<end>")}\n" +
            $"  now:       {(i < actual.Length ? actual[i] : "<end>")}");
    }

    private static string Render(ICryptoPolicy policy)
    {
        var lines = new List<string>();
        void Add(string section, string request, PolicyRequest r)
        {
            PolicyDecision d = policy.Evaluate(r);
            lines.Add($"{section}\t{request}\t{(d.IsAllowed ? "allow" : "deny")}\t{Escape(d.Reason)}");
        }

        CryptoOperation[] operations = Enum.GetValues<CryptoOperation>();

        // Every mechanism, without parameters: the allowed operations, and the reason given for each
        // refused operation (most share one reason, so distinct reasons only).
        foreach (CKM mechanism in Enum.GetValues<CKM>().Distinct())
        {
            var allowed = new List<string>();
            var reasons = new SortedSet<string>(StringComparer.Ordinal);
            foreach (CryptoOperation operation in operations)
            {
                PolicyDecision d = policy.Evaluate(new MechanismUseRequest(new Mechanism(mechanism), operation));
                if (d.IsAllowed)
                    allowed.Add(operation.ToString());
                else
                    reasons.Add(Escape(d.Reason).Replace(operation.ToString(), "{op}", StringComparison.Ordinal));
            }
            lines.Add($"mechanism\t{MechanismNames.Of(mechanism)}\tallow: {(allowed.Count == 0 ? "-" : string.Join(",", allowed))}\t{string.Join(" || ", reasons)}");
        }

        // AEAD tag and MAC lengths, single-part and message-based.
        foreach (int bits in new[] { 32, 64, 96, 104, 112, 120, 128 })
            Add("gcm", $"CkmAesGcmParams tag {bits}", Use(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], bits), CryptoOperation.Encrypt));
        foreach (int bytes in new[] { 4, 8, 12, 13, 14, 15, 16 })
            Add("gcm", $"CkmGcmMessageParams tag {bytes * 8}", Use(CKM.CKM_AES_GCM, CkmGcmMessageParams.ForEncrypt(new byte[12], bytes), CryptoOperation.Encrypt));
        foreach (int bytes in new[] { 4, 6, 8, 10, 12, 14, 16 })
        {
            Add("ccm", $"CkmAesCcmParams mac {bytes * 8}", Use(CKM.CKM_AES_CCM, new CkmAesCcmParams(16, new byte[12], [], bytes), CryptoOperation.Encrypt));
            Add("ccm", $"CkmCcmMessageParams mac {bytes * 8}", Use(CKM.CKM_AES_CCM, CkmCcmMessageParams.ForEncrypt(16, new byte[12], bytes), CryptoOperation.Encrypt));
        }

        // RSA-OAEP and RSA-PSS hashes and salt lengths.
        (CKM Hash, CKG Mgf)[] hashes =
        [
            (CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1), (CKM.CKM_SHA224, CKG.CKG_MGF1_SHA224), (CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256),
            (CKM.CKM_SHA384, CKG.CKG_MGF1_SHA384), (CKM.CKM_SHA512, CKG.CKG_MGF1_SHA512), (CKM.CKM_SHA3_256, CKG.CKG_MGF1_SHA3_256),
            (CKM.CKM_SHA256, CKG.CKG_MGF1_SHA1),
        ];
        foreach ((CKM hash, CKG mgf) in hashes)
        {
            string name = $"{MechanismNames.Of(hash)}/{mgf}";
            Add("oaep", name, Use(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(hash, mgf), CryptoOperation.Encrypt));
            foreach (int salt in new[] { 0, 20, 32, 64 })
            {
                foreach (CryptoOperation operation in new[] { CryptoOperation.Sign, CryptoOperation.Verify })
                {
                    Add("pss", $"CKM_RSA_PKCS_PSS {name} salt {salt} {operation}", Use(CKM.CKM_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(hash, mgf, salt), operation));
                    Add("pss", $"CKM_SHA256_RSA_PKCS_PSS {name} salt {salt} {operation}", Use(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(hash, mgf, salt), operation));
                }
            }
        }

        // Raw parameter bytes on parameter-checked mechanisms.
        foreach (CKM mechanism in new[] { CKM.CKM_AES_GCM, CKM.CKM_AES_CCM, CKM.CKM_RSA_PKCS_OAEP, CKM.CKM_RSA_PKCS_PSS, CKM.CKM_SHA256_RSA_PKCS_PSS, CKM.CKM_ECDH1_DERIVE, CKM.CKM_HKDF_DERIVE, CKM.CKM_PKCS5_PBKD2 })
        {
            CryptoOperation operation = mechanism switch
            {
                CKM.CKM_RSA_PKCS_PSS or CKM.CKM_SHA256_RSA_PKCS_PSS => CryptoOperation.Sign,
                CKM.CKM_ECDH1_DERIVE or CKM.CKM_HKDF_DERIVE => CryptoOperation.Derive,
                CKM.CKM_PKCS5_PBKD2 => CryptoOperation.GenerateKey,
                _ => CryptoOperation.Encrypt,
            };
            Add("raw", MechanismNames.Of(mechanism), new MechanismUseRequest(new Mechanism(mechanism, new byte[16]), operation));
        }

        // KDF PRFs.
        foreach (CKP prf in Enum.GetValues<CKP>())
            Add("pbkdf2", prf.ToString(), Use(CKM.CKM_PKCS5_PBKD2, new CkmPkcs5Pbkd2Params(new byte[16], 600_000, prf, "password"u8), CryptoOperation.GenerateKey));
        CKM[] prfs = [CKM.CKM_SHA_1_HMAC, CKM.CKM_SHA224_HMAC, CKM.CKM_SHA256_HMAC, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC, CKM.CKM_SHA3_256_HMAC, CKM.CKM_AES_CMAC, CKM.CKM_MD5_HMAC];
        foreach (CKM prf in prfs)
        {
            Add("sp800-108", MechanismNames.Of(prf), Use(CKM.CKM_SP800_108_COUNTER_KDF, CkmSp800108KdfParams.CounterModeHmac(prf, "label"u8, "context"u8), CryptoOperation.Derive));
            Add("hkdf", MechanismNames.Of(prf), Use(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, prf, "salt"u8, "info"u8), CryptoOperation.Derive));
        }

        // KDF parameter shapes beyond the counter-mode HMAC helper.
        foreach (CKM prf in new[] { CKM.CKM_SHA256_HMAC, CKM.CKM_SHA_1_HMAC })
        {
            Add("sp800-108", $"feedback {MechanismNames.Of(prf)}", Use(CKM.CKM_SP800_108_FEEDBACK_KDF,
                CkmSp800108KdfParams.Feedback(prf).IterationCounter().ByteArray("label"u8).Build(), CryptoOperation.Derive));
            Add("sp800-108", $"double-pipeline {MechanismNames.Of(prf)}", Use(CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF,
                CkmSp800108KdfParams.DoublePipeline(prf).IterationCounter().ByteArray("label"u8).Build(), CryptoOperation.Derive));
            Add("hkdf", $"no salt {MechanismNames.Of(prf)}", Use(CKM.CKM_HKDF_DERIVE,
                CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, prf, "info"u8), CryptoOperation.Derive));
            Add("hkdf", $"expand only {MechanismNames.Of(prf)}", Use(CKM.CKM_HKDF_DERIVE,
                CkmHkdfParams.WithoutSalt(HkdfOperation.ExpandOnly, prf, "info"u8), CryptoOperation.Derive));
        }

        // HashML-DSA / HashSLH-DSA with an explicit pre-hash.
        foreach (CKM mechanism in new[] { CKM.CKM_HASH_ML_DSA, CKM.CKM_HASH_SLH_DSA })
            foreach (CKM hash in new[] { CKM.CKM_SHA_1, CKM.CKM_SHA256, CKM.CKM_SHA512, CKM.CKM_SHA3_256 })
                Add("pqc-prehash", $"{MechanismNames.Of(mechanism)} {MechanismNames.Of(hash)}",
                    Use(mechanism, new CkmHashPqcSignParams(hash), CryptoOperation.Sign));

        // Key agreement: the KDF inside ECDH parameters, the KDF and key-type requests.
        byte[] point = [0x04, .. new byte[64]];
        foreach (CKD kdf in Enum.GetValues<CKD>().Distinct())
        {
            Add("ecdh-params", kdf.ToString(), Use(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(kdf, point), CryptoOperation.Derive));
            Add("kdf", kdf.ToString(), new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, kdf));
        }
        foreach (CKK keyType in Enum.GetValues<CKK>().Distinct())
            Add("key-agreement-key", keyType.ToString(), new KeyAgreementKeyRequest(CKM.CKM_ECDH1_DERIVE, keyType));

        // Hashes, curves, RSA sizes.
        string[] hashNames = ["MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512", "RIPEMD160"];
        foreach (string hash in hashNames)
            foreach (CryptoOperation operation in new[] { CryptoOperation.Digest, CryptoOperation.Sign, CryptoOperation.Verify })
                Add("hash", $"{hash} {operation}", new HashUseRequest(new HashAlgorithmName(hash), operation));
        foreach (PropertyInfo property in typeof(Pkcs11ECCurve.NamedCurves).GetProperties(BindingFlags.Public | BindingFlags.Static)
                     .Where(p => p.PropertyType == typeof(Pkcs11ECCurve)))
            Add("curve", property.Name, new EcKeyGenerationRequest((Pkcs11ECCurve)property.GetValue(null)!));
        foreach (CKM mechanism in new[] { CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_X9_31_KEY_PAIR_GEN })
            foreach (int bits in new[] { 1024, 1536, 2047, 2048, 3072, 4096 })
                Add("rsa-keygen", $"{MechanismNames.Of(mechanism)} {bits}", new RsaKeyGenerationRequest(mechanism, bits));

        // Key templates and exports.
        using (var sensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true))
        using (var notSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false))
        using (var extractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true))
        {
            Add("template", "secret, CKA_SENSITIVE=true", new KeyTemplateRequest(CKO.CKO_SECRET_KEY, [sensitive]));
            Add("template", "secret, CKA_SENSITIVE=false", new KeyTemplateRequest(CKO.CKO_SECRET_KEY, [notSensitive]));
            Add("template", "secret, CKA_EXTRACTABLE=true", new KeyTemplateRequest(CKO.CKO_SECRET_KEY, [extractable]));
            Add("template", "private, CKA_SENSITIVE=false", new KeyTemplateRequest(CKO.CKO_PRIVATE_KEY, [notSensitive]));
        }
        foreach (SecretExportKind kind in Enum.GetValues<SecretExportKind>())
            Add("export", kind.ToString(), new SecretExportRequest(kind));
        Add("export", "EcdhSharedSecret with mechanism and base key", new SecretExportRequest(SecretExportKind.EcdhSharedSecret)
        {
            Mechanism = CKM.CKM_ECDH1_DERIVE,
            BaseKeyClass = CKO.CKO_PRIVATE_KEY,
            BaseKeyType = CKK.CKK_EC,
        });

        // A copy keeps every verdict; only the hints that name the policy change.
        ICryptoPolicy copy = ((ComposedCryptoPolicy)policy).ToBuilder("Derived").Build();
        void AddCopy(string request, PolicyRequest r)
        {
            PolicyDecision d = copy.Evaluate(r);
            lines.Add($"derived-copy\t{request}\t{(d.IsAllowed ? "allow" : "deny")}\t{Escape(d.Reason)}");
        }
        AddCopy("unlisted vendor mechanism", new MechanismUseRequest(new Mechanism((CKM)0x80001234UL), CryptoOperation.Sign));
        AddCopy("CKM_DES3_CBC Decrypt", new MechanismUseRequest(new Mechanism(CKM.CKM_DES3_CBC), CryptoOperation.Decrypt));
        foreach (SecretExportKind kind in Enum.GetValues<SecretExportKind>())
            AddCopy($"export {kind}", new SecretExportRequest(kind));

        lines.Sort(StringComparer.Ordinal);
        return string.Join('\n', lines) + "\n";
    }

    private static MechanismUseRequest Use(CKM mechanism, MechanismParameters parameters, CryptoOperation operation) =>
        new(new Mechanism(mechanism, parameters), operation);

    private static string Escape(string? text) =>
        (text ?? "").Replace("\t", " ", StringComparison.Ordinal).Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);

    /// <summary>Walks up from the test assembly's own directory to the directory containing <c>src/KerckhoffsLabs.sln</c>.</summary>
    private static string FindRepoRoot()
    {
        for (DirectoryInfo? dir = new(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Join(dir.FullName, "src", "KerckhoffsLabs.sln")))
                return dir.FullName;
        }
        throw new InvalidOperationException(
            $"Could not locate the repo root (looked for src/KerckhoffsLabs.sln walking up from {AppContext.BaseDirectory}).");
    }
}
