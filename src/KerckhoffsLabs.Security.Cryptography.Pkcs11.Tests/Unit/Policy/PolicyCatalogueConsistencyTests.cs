using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

#pragma warning disable KLPKCS11007, KLPKCS11008, KLPKCS11009, KLPKCS11010 // weak inputs are the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>
/// Structural invariants of both restrictive catalogues: nothing is both allowed and documented as
/// refused, every entry explains itself, every NistApproved entry cites NIST, and the documented deny list
/// never decides a verdict.
/// </summary>
public sealed class PolicyCatalogueConsistencyTests
{
    public static TheoryData<string> Catalogues => ["Recommended", "NistApproved"];

    private static PolicyCatalogue CatalogueFor(string name) => name switch
    {
        "Recommended" => CryptoPolicy.Recommended.Catalogue,
        "NistApproved" => CryptoPolicy.NistApproved.Catalogue,
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private static string Describe<T>(IEnumerable<T> items) => string.Join(", ", items.Select(i => i!.ToString()).Order());

    [Theory]
    [MemberData(nameof(Catalogues))]
    public void NoMechanism_IsBothAllowedAndDocumentedRefused(string name)
    {
        PolicyCatalogue c = CatalogueFor(name);
        // By CKM value: aliases share a value, and the evaluator looks entries up by value.
        var allowed = c.AllowedMechanisms.Keys.Select(k => (ulong)k).ToHashSet();
        var overlap = c.DocumentedRefusedMechanisms.Keys.Where(k => allowed.Contains((ulong)k)).ToList();
        Assert.True(overlap.Count == 0, $"{name}: allowed and documented-refused: {Describe(overlap)}");
    }

    [Theory]
    [MemberData(nameof(Catalogues))]
    public void NoHashCurveOrKdf_IsBothAllowedAndDocumentedRefused(string name)
    {
        PolicyCatalogue c = CatalogueFor(name);
        Assert.Empty(c.AllowedHashes.Keys.Intersect(c.DocumentedRefusedHashes.Keys));
        Assert.Empty(c.AllowedCurves.Keys.Intersect(c.DocumentedRefusedCurves.Keys));
        Assert.Empty(c.AllowedKdfs.Keys.Intersect(c.DocumentedRefusedKdfs.Keys));
        Assert.Empty(c.AllowedKeyAgreementKeyTypes.Keys.Intersect(c.DocumentedRefusedKeyAgreementKeyTypes.Keys));
    }

    [Theory]
    [MemberData(nameof(Catalogues))]
    public void NoKdfPrf_IsBothAllowedAndDocumentedRefused(string name)
    {
        PolicyCatalogue c = CatalogueFor(name);
        var allowed = c.AllowedKdfPrfs.Values.SelectMany(prfs => prfs).ToHashSet(StringComparer.Ordinal);
        Assert.NotEmpty(allowed);
        Assert.Empty(allowed.Intersect(c.DocumentedRefusedPrfs.Keys));
    }

    [Theory]
    [MemberData(nameof(Catalogues))]
    public void EveryEntry_HasANonEmptyRationaleOrReason(string name)
    {
        PolicyCatalogue c = CatalogueFor(name);
        Assert.All(c.AllowedMechanisms, kv => Assert.False(string.IsNullOrWhiteSpace(kv.Value.Rationale), kv.Key.ToString()));
        Assert.All(c.AllowedHashes, kv => Assert.False(string.IsNullOrWhiteSpace(kv.Value.Rationale), kv.Key));
        Assert.All(c.AllowedCurves, kv => Assert.False(string.IsNullOrWhiteSpace(kv.Value), kv.Key));
        Assert.All(c.AllowedKdfs, kv => Assert.False(string.IsNullOrWhiteSpace(kv.Value), kv.Key.ToString()));
        Assert.All(c.AllowedKeyAgreementKeyTypes, kv => Assert.False(string.IsNullOrWhiteSpace(kv.Value), kv.Key.ToString()));
        Assert.All(c.DocumentedRefusedMechanisms, kv => Assert.False(string.IsNullOrWhiteSpace(kv.Value.Reason), kv.Key.ToString()));
        Assert.All(c.DocumentedRefusedHashes, kv => Assert.False(string.IsNullOrWhiteSpace(kv.Value.Reason), kv.Key));
        Assert.All(c.DocumentedRefusedCurves, kv => Assert.False(string.IsNullOrWhiteSpace(kv.Value.Reason), kv.Key));
        Assert.All(c.DocumentedRefusedKdfs, kv => Assert.False(string.IsNullOrWhiteSpace(kv.Value.Reason), kv.Key.ToString()));
        Assert.All(c.DocumentedRefusedKeyAgreementKeyTypes, kv => Assert.False(string.IsNullOrWhiteSpace(kv.Value.Reason), kv.Key.ToString()));
        Assert.All(c.DocumentedRefusedPrfs, kv => Assert.False(string.IsNullOrWhiteSpace(kv.Value.Reason), kv.Key));
    }

    [Fact]
    public void EveryNistApprovedAllowedEntry_CitesNist()
    {
        var citation = new Regex("(SP 800-|FIPS 1|FIPS 2)", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        PolicyCatalogue c = CryptoPolicy.NistApproved.Catalogue;
        Assert.All(c.AllowedMechanisms, kv => Assert.Matches(citation, kv.Value.Rationale));
        Assert.All(c.AllowedHashes, kv => Assert.Matches(citation, kv.Value.Rationale));
        Assert.All(c.AllowedCurves, kv => Assert.Matches(citation, kv.Value));
        Assert.All(c.AllowedKdfs, kv => Assert.Matches(citation, kv.Value));
        Assert.All(c.AllowedKeyAgreementKeyTypes, kv => Assert.Matches(citation, kv.Value));
    }

    // A documented refusal ends its sentence itself: the evaluator appends " Use {Alternative}." after it.
    [Theory]
    [MemberData(nameof(Catalogues))]
    public void EveryDocumentedReason_EndsWithAPeriod(string name)
    {
        PolicyCatalogue c = CatalogueFor(name);
        IEnumerable<(string Item, DocumentedRefusal Refusal)> all =
            c.DocumentedRefusedMechanisms.Select(kv => (kv.Key.ToString(), kv.Value))
                .Concat(c.DocumentedRefusedHashes.Select(kv => (kv.Key, kv.Value)))
                .Concat(c.DocumentedRefusedCurves.Select(kv => (kv.Key, kv.Value)))
                .Concat(c.DocumentedRefusedKdfs.Select(kv => (kv.Key.ToString(), kv.Value)))
                .Concat(c.DocumentedRefusedKeyAgreementKeyTypes.Select(kv => (kv.Key.ToString(), kv.Value)))
                .Concat(c.DocumentedRefusedPrfs.Select(kv => (kv.Key, kv.Value)));
        Assert.All(all, e => Assert.True(e.Refusal.Reason.EndsWith('.'), $"{name} {e.Item}: '{e.Refusal.Reason}'"));
    }

    // === The documented deny list never decides a verdict ====================

    private static ComposedCryptoPolicy PolicyFor(string name) => name switch
    {
        "Recommended" => CryptoPolicy.Recommended,
        "NistApproved" => CryptoPolicy.NistApproved,
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private static PolicyCatalogue WithoutDocumentedRefusals(PolicyCatalogue c) => new()
    {
        AllowedMechanisms = c.AllowedMechanisms,
        AllowedVendorMechanisms = c.AllowedVendorMechanisms,
        AllowedHashes = c.AllowedHashes,
        AllowedCurves = c.AllowedCurves,
        AllowedKdfs = c.AllowedKdfs,
        AllowedKeyAgreementKeyTypes = c.AllowedKeyAgreementKeyTypes,
        AllowedKdfPrfs = c.AllowedKdfPrfs,
        RsaKeyGeneration = c.RsaKeyGeneration,
        KeyTemplate = c.KeyTemplate,
        SecretExport = c.SecretExport,
        UnlistedMechanismHint = c.UnlistedMechanismHint,
        DocumentedRefusedMechanisms = FrozenDictionary<CKM, DocumentedRefusal>.Empty,
        DocumentedRefusedHashes = FrozenDictionary<string, DocumentedRefusal>.Empty,
        DocumentedRefusedCurves = FrozenDictionary<string, DocumentedRefusal>.Empty,
        DocumentedRefusedKdfs = FrozenDictionary<CKD, DocumentedRefusal>.Empty,
        DocumentedRefusedKeyAgreementKeyTypes = FrozenDictionary<CKK, DocumentedRefusal>.Empty,
        DocumentedRefusedPrfs = FrozenDictionary<string, DocumentedRefusal>.Empty,
    };

    private static IEnumerable<PolicyRequest> EveryRequest(PolicyCatalogue c)
    {
        foreach (CKM mech in Enum.GetValues<CKM>())
            foreach (CryptoOperation op in Enum.GetValues<CryptoOperation>())
            {
                yield return new MechanismUseRequest(new Mechanism(mech), op);
                yield return new MechanismUseRequest(RecommendedPolicyTests.ValidMechanismFor(mech), op);
            }

        foreach (string hash in c.AllowedHashes.Keys.Concat(c.DocumentedRefusedHashes.Keys).Append("SHA512_256").Append("NOT-A-HASH"))
            foreach (CryptoOperation op in Enum.GetValues<CryptoOperation>())
                yield return new HashUseRequest(new HashAlgorithmName(hash), op);

        foreach (string oid in c.AllowedCurves.Keys.Concat(c.DocumentedRefusedCurves.Keys).Append("1.2.999.1"))
            yield return new EcKeyGenerationRequest(Pkcs11ECCurve.CreateFromValue(oid));

        foreach (CKD kdf in Enum.GetValues<CKD>())
            yield return new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, kdf);

        foreach (CKK keyType in Enum.GetValues<CKK>())
            yield return new KeyAgreementKeyRequest(CKM.CKM_ECDH1_DERIVE, keyType);

        foreach (CKM rsa in (CKM[])[CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_X9_31_KEY_PAIR_GEN])
            foreach (int bits in (int[])[1024, 2048, 4096])
                yield return new RsaKeyGenerationRequest(rsa, bits);
    }

    // Emptying every DocumentedRefused* table must not change a single verdict: an item is denied because
    // it is absent from the allow-list, and the documentation only words the denial.
    [Theory]
    [MemberData(nameof(Catalogues))]
    public void EmptyingTheDocumentedDenyList_ChangesNoVerdict(string name)
    {
        ComposedCryptoPolicy policy = PolicyFor(name);
        PolicyCatalogue original = CatalogueFor(name);
        PolicyCatalogue stripped = WithoutDocumentedRefusals(original);
        int compared = 0;

        foreach (PolicyRequest request in EveryRequest(original))
        {
            bool expected = policy.Evaluate(request).IsAllowed;
            Assert.Equal(expected, CatalogueEvaluator.Evaluate(original, policy.Name, request).IsAllowed);
            PolicyDecision withoutDocs = CatalogueEvaluator.Evaluate(stripped, policy.Name, request);
            Assert.True(expected == withoutDocs.IsAllowed, $"{name}: {request} changed verdict without the documented deny list");
            compared++;
        }

        Assert.True(compared > 1000, $"only {compared} requests compared");
    }

    // === The documented PRF deny list decides nothing ========================
    // The PRF checks live inside the KDF mechanisms' parameter checks, which the "empty the documented
    // tables" comparison above cannot reach: it never supplies a refused PRF. Drive every PRF value
    // through every KDF mechanism and pin the verdict to the allow-list alone — allowed exactly when the
    // PRF is on the family's allow-list, whether or not it is also documented as refused.

    private static ComposedCryptoPolicy PolicyNamed(string name) => name switch
    {
        "Recommended" => CryptoPolicy.Recommended,
        "NistApproved" => CryptoPolicy.NistApproved,
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private static FrozenSet<string> AllowedPrfs(PolicyCatalogue catalogue, string familyPrefix) =>
        Assert.Single(catalogue.AllowedKdfPrfs, kv => kv.Key.StartsWith(familyPrefix, StringComparison.Ordinal)).Value;

    private static IEnumerable<(Mechanism Mechanism, CryptoOperation Operation, string Prf, string Family)> KdfRequestsOverEveryPrf()
    {
        foreach (CKP prf in Enum.GetValues<CKP>())
            foreach (CryptoOperation op in new[] { CryptoOperation.GenerateKey, CryptoOperation.Derive })
                yield return (new Mechanism(CKM.CKM_PKCS5_PBKD2, new CkmPkcs5Pbkd2Params(new byte[16], 1000, prf, "pw"u8)), op, prf.ToString(), "PBKDF2");

        foreach (CKM prf in Enum.GetValues<CKM>().Distinct())
        {
            var sp800108 = CkmSp800108KdfParams.CounterModeHmac(prf, "label"u8, "context"u8);
            foreach (CKM kdf in new[] { CKM.CKM_SP800_108_COUNTER_KDF, CKM.CKM_SP800_108_FEEDBACK_KDF, CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF })
                yield return (new Mechanism(kdf, sp800108), CryptoOperation.Derive, prf.ToString(), "SP 800-108");

            var hkdf = CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, prf);
            yield return (new Mechanism(CKM.CKM_HKDF_DERIVE, hkdf), CryptoOperation.Derive, prf.ToString(), "HKDF");
        }
    }

    [Theory]
    [MemberData(nameof(Catalogues))]
    public void KdfPrfVerdicts_FollowTheAllowList_AndIgnoreTheDocumentedPrfDenyList(string name)
    {
        ComposedCryptoPolicy policy = PolicyNamed(name);
        PolicyCatalogue catalogue = CatalogueFor(name);
        int documentedRefusedSeen = 0;

        foreach ((Mechanism mechanism, CryptoOperation op, string prf, string family) in KdfRequestsOverEveryPrf())
        {
            // The KDF mechanism itself must be allowed for this operation, or the PRF is never reached.
            if (!catalogue.AllowedMechanisms.TryGetValue(mechanism.Type, out MechanismRule? rule)
                || !(rule.Operations | rule.LegacyOperations).Contains(op))
                continue;

            bool expected = AllowedPrfs(catalogue, family).Contains(prf);
            PolicyDecision decision = policy.Evaluate(new MechanismUseRequest(mechanism, op));
            Assert.True(expected == decision.IsAllowed,
                $"{name}: {mechanism.Type} for {op} with PRF {prf} — expected {(expected ? "allowed" : "denied")}, got {(decision.IsAllowed ? "allowed" : decision.Reason)}");

            if (catalogue.DocumentedRefusedPrfs.ContainsKey(prf))
                documentedRefusedSeen++;
        }

        // Every documented refused PRF must actually have been driven through, or the test proves nothing about them.
        Assert.True(documentedRefusedSeen >= catalogue.DocumentedRefusedPrfs.Count,
            $"{name}: only {documentedRefusedSeen} requests used a documented refused PRF ({catalogue.DocumentedRefusedPrfs.Count} documented).");
    }
}
