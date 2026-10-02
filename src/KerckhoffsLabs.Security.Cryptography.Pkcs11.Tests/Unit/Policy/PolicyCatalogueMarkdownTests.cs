using System.Collections.Frozen;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.BuiltIn;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

#pragma warning disable KLPKCS11007, KLPKCS11008, KLPKCS11009, KLPKCS11010 // weak inputs are the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>
/// Exercises <see cref="PolicyCatalogueMarkdown"/> against a small, hand-built <see cref="PolicyCatalogue"/> —
/// independent of the real NistApproved/Recommended catalogues — covering ordering, escaping, section presence,
/// and the footer. <see cref="PolicyDocsAreCurrentTests"/> covers the real catalogues.
/// </summary>
public sealed class PolicyCatalogueMarkdownTests
{
    // Two families (AES, EC) so family-then-name ordering is observable. Within AES, two mechanisms
    // ("CKM_AES_GMAC" before "CKM_AES_KEY_GEN" ordinally) exercise the Operations/LegacyOperations/
    // ParameterCheck columns. The rationale below deliberately embeds a "|" and a newline to exercise
    // escaping.
    private const string PipeRationale = "Allowed for A | B usage.\nSecond line.";

    private static PolicyCatalogue BuildCatalogue(PolicyDocumentation documentation = PolicyDocumentation.None) => new()
    {
        Documentation = documentation,
        AllowedMechanisms = new Dictionary<CKM, MechanismRule>
        {
            [CKM.CKM_AES_KEY_GEN] = new(CryptoOperations.GenerateKey, CryptoOperations.None, null, "AES key generation."),
            [CKM.CKM_AES_GMAC] = new(CryptoOperations.Sign, CryptoOperations.Verify, null, PipeRationale),
            [CKM.CKM_RSA_PKCS_OAEP] = new(CryptoOperations.Encrypt, CryptoOperations.None,
                MechanismCheck.FromDelegate((_, _) => PolicyDecision.Allow, "requires an allowed hash"), "OAEP key transport."),
            [CKM.CKM_ECDSA] = new(CryptoOperations.Sign | CryptoOperations.Verify, CryptoOperations.None, null, "ECDSA signatures."),
        }.ToFrozenDictionary(),
        AllowedVendorMechanisms = new Dictionary<ulong, MechanismRule>
        {
            [0x8000_0002UL] = new(CryptoOperations.Encrypt, CryptoOperations.None, null, "Second vendor mechanism."),
            [0x8000_0001UL] = new(CryptoOperations.Encrypt, CryptoOperations.None, null, "First vendor mechanism."),
        }.ToFrozenDictionary(),
        AllowedHashes = new Dictionary<string, AllowedHash>(StringComparer.Ordinal)
        {
            ["SHA256"] = new(CryptoOperations.Sign | CryptoOperations.Verify, "SHA-2."),
        }.ToFrozenDictionary(StringComparer.Ordinal),
        AllowedCurves = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [Pkcs11ECCurve.NamedCurves.NistP256.Oid!] = "NIST prime curve.",
            ["1.2.999.1"] = "An OID with no known friendly name.",
        }.ToFrozenDictionary(StringComparer.Ordinal),
        AllowedKdfs = new Dictionary<CKD, string>
        {
            [CKD.CKD_SHA256_KDF] = "ANSI X9.63 KDF.",
        }.ToFrozenDictionary(),
        AllowedKeyAgreementKeyTypes = new Dictionary<CKK, string>
        {
            [CKK.CKK_EC] = "ECDH over a prime curve.",
        }.ToFrozenDictionary(),
        AllowedKdfPrfs = new Dictionary<string, FrozenSet<string>>(StringComparer.Ordinal)
        {
            ["HKDF"] = FrozenSet.ToFrozenSet(["CKM_SHA384", "CKM_SHA256"], StringComparer.Ordinal),
        }.ToFrozenDictionary(StringComparer.Ordinal),
        RsaKeyGeneration = RsaKeyGenerationRule.FromDelegate(_ => PolicyDecision.Allow, "Modulus must be at least 2048 | 4096 bits."),
        KeyTemplate = KeyTemplateRule.FromDelegate(_ => PolicyDecision.Allow, "CKA_SENSITIVE=false is refused."),
        SecretExport = SecretExportRule.FromDelegate(_ => PolicyDecision.Allow, "Export is refused."),
        DocumentedRefusedMechanisms = new Dictionary<CKM, DocumentedRefusal>
        {
            [CKM.CKM_MD5] = new("MD5 is broken.", "SHA256"),
            [CKM.CKM_DES_ECB] = new("ECB leaks structure | is bad.", null),
        }.ToFrozenDictionary(),
        DocumentedRefusedHashes = new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal)
        {
            ["SHA1"] = new("SHA-1 is broken.", "SHA256"),
        }.ToFrozenDictionary(StringComparer.Ordinal),
        DocumentedRefusedCurves = new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal)
        {
            ["1.2.999.2"] = new("Too weak.", "NistP256"),
        }.ToFrozenDictionary(StringComparer.Ordinal),
        DocumentedRefusedKdfs = new Dictionary<CKD, DocumentedRefusal>
        {
            [CKD.CKD_NULL] = new("No KDF at all.", "CKD_SHA256_KDF"),
        }.ToFrozenDictionary(),
        DocumentedRefusedKeyAgreementKeyTypes = new Dictionary<CKK, DocumentedRefusal>
        {
            [CKK.CKK_EC_MONTGOMERY] = new("Montgomery keys are not approved.", "a CKK_EC key"),
        }.ToFrozenDictionary(),
        DocumentedRefusedPrfs = new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal)
        {
            ["CKM_SHA_1_HMAC"] = new("SHA-1 is broken.", "a stronger PRF"),
        }.ToFrozenDictionary(StringComparer.Ordinal),
    };

    [Fact]
    public void Render_ThrowsOnNullCatalogue()
        => Assert.Throws<ArgumentNullException>(() => PolicyCatalogueMarkdown.Render(null!, "Recommended"));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Render_ThrowsOnBlankPolicyName(string? policyName)
        // ArgumentException.ThrowIfNullOrWhiteSpace throws ArgumentNullException for null specifically
        // (a subtype of ArgumentException) and plain ArgumentException for "" / " " — ThrowsAny accepts either.
        => Assert.ThrowsAny<ArgumentException>(() => PolicyCatalogueMarkdown.Render(BuildCatalogue(), policyName!));

    [Fact]
    public void Render_UsesOnlyLineFeeds()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "Recommended");
        Assert.DoesNotContain('\r', markdown);
    }

    [Fact]
    public void Render_IsDeterministicAcrossCalls()
    {
        PolicyCatalogue catalogue = BuildCatalogue();
        string first = PolicyCatalogueMarkdown.Render(catalogue, "Recommended");
        string second = PolicyCatalogueMarkdown.Render(catalogue, "Recommended");
        Assert.Equal(first, second);
    }

    [Fact]
    public void Render_EndsWithTheDenyByDefaultFooter()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "Recommended");
        string[] lines = markdown.Split('\n');
        // The string ends with "\n", so the meaningful last line is second-to-last after Split.
        Assert.Equal("Anything not listed above is denied by default.", lines[^2]);
    }

    [Fact]
    public void Render_EscapesPipesAndNewlinesInFreeText()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "Recommended");
        Assert.Contains("Allowed for A \\| B usage. Second line.", markdown);
        Assert.Contains("ECB leaks structure \\| is bad.", markdown);
        Assert.Contains("Modulus must be at least 2048 \\| 4096 bits.", markdown);
    }

    [Fact]
    public void Render_GroupsAllowedMechanismsByFamilyThenName_InOrdinalOrder()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "Recommended");
        int aesHeading = markdown.IndexOf("### AES", StringComparison.Ordinal);
        int ecHeading = markdown.IndexOf("### EC", StringComparison.Ordinal);
        int gmac = markdown.IndexOf("CKM_AES_GMAC", StringComparison.Ordinal);
        int keyGen = markdown.IndexOf("CKM_AES_KEY_GEN", StringComparison.Ordinal);

        Assert.True(aesHeading >= 0 && ecHeading > aesHeading, "AES family must precede EC (ordinal).");
        Assert.True(gmac >= 0 && keyGen > gmac, "Within AES, CKM_AES_GMAC must precede CKM_AES_KEY_GEN (ordinal).");
    }

    [Fact]
    public void Render_RendersOperationsLegacyOperationsAndParameterCheckColumns()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "Recommended");
        Assert.Contains("| `CKM_AES_GMAC` | Sign | Verify | — | Allowed for A \\| B usage. Second line. |", markdown);
        Assert.Contains("| `CKM_RSA_PKCS_OAEP` | Encrypt | — | requires an allowed hash | OAEP key transport. |", markdown);
    }

    [Fact]
    public void Render_RendersVendorMechanismsSortedByRawValue()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "Recommended");
        int first = markdown.IndexOf("0x80000001", StringComparison.Ordinal);
        int second = markdown.IndexOf("0x80000002", StringComparison.Ordinal);
        Assert.True(first >= 0 && second > first);
    }

    [Fact]
    public void Render_RendersCurveFriendlyNameAndFallsBackForUnknownOid()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "Recommended");
        Assert.Contains("`nistP256`", markdown);
        Assert.Contains("*(unnamed)*", markdown);
    }

    [Fact]
    public void Render_RendersAllowedKdfPrfsSortedOrdinally()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "Recommended");
        Assert.Contains("| HKDF | `CKM_SHA256`, `CKM_SHA384` |", markdown);
    }

    [Fact]
    public void Render_RendersKeyAgreementKeyTypes()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "Recommended");
        Assert.Contains("## Allowed key-agreement key types", markdown);
        Assert.Contains("| `CKK_EC` | ECDH over a prime curve. |", markdown);
        Assert.Contains("### Key-agreement key types", markdown);
        Assert.Contains("| `CKK_EC_MONTGOMERY` | Montgomery keys are not approved. | a CKK_EC key |", markdown);
    }

    // Recommended refuses no key-agreement key type it documents, so the page carries no empty table.
    [Fact]
    public void Render_OmitsTheKeyTypeRefusalSection_WhenThereAreNone()
    {
        string markdown = PolicyCatalogueMarkdown.Render(CryptoPolicy.Recommended.Catalogue, "Recommended");
        Assert.DoesNotContain("### Key-agreement key types", markdown);
    }

    [Fact]
    public void Render_RendersRulesRationale()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "Recommended");
        Assert.Contains("CKA_SENSITIVE=false is refused.", markdown);
        Assert.Contains("Export is refused.", markdown);
    }

    [Fact]
    public void Render_RendersDocumentedRefusalsWithReasonAndAlternative()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "Recommended");
        Assert.Contains("| `CKM_MD5` | MD5 is broken. | SHA256 |", markdown);
        Assert.Contains("| `CKM_DES_ECB` | ECB leaks structure \\| is bad. | — |", markdown);
        Assert.Contains("| `SHA1` | SHA-1 is broken. | SHA256 |", markdown);
        Assert.Contains("| `CKD_NULL` | No KDF at all. | CKD_SHA256_KDF |", markdown);
        Assert.Contains("| `CKM_SHA_1_HMAC` | SHA-1 is broken. | a stronger PRF |", markdown);
    }

    [Fact]
    public void Render_IncludesAllExpectedSectionsAndFooter()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "Recommended");
        Assert.Contains("## Allowed mechanisms", markdown);
        Assert.Contains("## Allowed hashes", markdown);
        Assert.Contains("## Allowed EC curves", markdown);
        Assert.Contains("## Allowed key-agreement KDFs", markdown);
        Assert.Contains("## Allowed KDF PRFs", markdown);
        Assert.Contains("## Rules", markdown);
        Assert.Contains("## Documented refusals", markdown);
        Assert.Contains("## Known limits", markdown);
        Assert.Contains("Anything not listed above is denied by default.", markdown);
    }

    [Theory]
    [InlineData("Recommended")]
    public void Render_IncludesTheExtensionPointForTheRecommendedFamily(string policyName)
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(PolicyDocumentation.Recommended), policyName);
        Assert.Contains("## Extension point", markdown);
        Assert.Contains("ToBuilder(name)", markdown);
    }

    [Fact]
    public void Render_OmitsTheExtensionPointAndFipsDisclaimerForANonRecommendedPolicy()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "RecommendedApp");
        Assert.DoesNotContain("## Extension point", markdown);
        Assert.DoesNotContain("FIPS 140-3", markdown);
    }

    [Fact]
    public void Render_IncludesTheFipsDisclaimerAndBaselineOnlyForNistApproved()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(PolicyDocumentation.NistApproved), "NistApproved");
        Assert.Contains("not a FIPS 140-3 certification", markdown);
        Assert.Contains(NistApprovedDefinition.Baseline, markdown);
        Assert.DoesNotContain("## Extension point", markdown);
    }

    // --- Known limits ---

    // Recommended allows CKM_EC_MONTGOMERY_KEY_PAIR_GEN, so "only generating such a key is refused" is true
    // of NistApproved alone.
    [Fact]
    public void Render_TheX25519EcdhRefusal_AppearsOnlyForNistApproved()
    {
        Assert.Contains("| `CKK_EC_MONTGOMERY` | SP 800-56A", PolicyCatalogueMarkdown.Render(CryptoPolicy.NistApproved.Catalogue, "NistApproved"));
        Assert.Contains("| `CKK_EC_MONTGOMERY` | X25519 / X448", PolicyCatalogueMarkdown.Render(CryptoPolicy.Recommended.Catalogue, "Recommended"));
    }

    // --- Wording ---

    [Fact]
    public void Render_ExtensionPointParagraph_DoesNotPlaceTheDenyListBelowIt()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(PolicyDocumentation.Recommended), "Recommended");
        int extension = markdown.IndexOf("## Extension point", StringComparison.Ordinal);
        int denyList = markdown.IndexOf("## Documented refusals", StringComparison.Ordinal);
        string paragraph = markdown[extension..markdown.IndexOf("## Known limits", StringComparison.Ordinal)];

        Assert.True(denyList >= 0 && extension > denyList);
        Assert.DoesNotContain("below", paragraph, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_Rules_DoNotClaimToApplyToEveryRequest()
    {
        string markdown = PolicyCatalogueMarkdown.Render(BuildCatalogue(), "Recommended");
        Assert.DoesNotContain("regardless of mechanism", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("apply to every request", markdown, StringComparison.Ordinal);
    }

    // --- Preferred names for aliased CKM values ---

    // Every CKM value with more than one name, mapped to the current PKCS#11 v3 name. A new alias in CKM
    // fails EveryAliasedCkmValue_HasAPreferredName until it is added here and to MechanismNames.
    private static readonly (CKM Value, string Preferred)[] Aliases =
    [
        (CKM.CKM_CAST128_KEY_GEN, "CKM_CAST128_KEY_GEN"),
        (CKM.CKM_CAST128_ECB, "CKM_CAST128_ECB"),
        (CKM.CKM_CAST128_CBC, "CKM_CAST128_CBC"),
        (CKM.CKM_CAST128_MAC, "CKM_CAST128_MAC"),
        (CKM.CKM_CAST128_MAC_GENERAL, "CKM_CAST128_MAC_GENERAL"),
        (CKM.CKM_CAST128_CBC_PAD, "CKM_CAST128_CBC_PAD"),
        (CKM.CKM_PBE_MD5_CAST128_CBC, "CKM_PBE_MD5_CAST128_CBC"),
        (CKM.CKM_PBE_SHA1_CAST128_CBC, "CKM_PBE_SHA1_CAST128_CBC"),
        (CKM.CKM_EC_KEY_PAIR_GEN, "CKM_EC_KEY_PAIR_GEN"),
        (CKM.CKM_DSA_PROBABILISTIC_PARAMETER_GEN, "CKM_DSA_PROBABILISTIC_PARAMETER_GEN"),
        (CKM.CKM_SHA3_224_KEY_DERIVE, "CKM_SHA3_224_KEY_DERIVE"),
        (CKM.CKM_SHA3_256_KEY_DERIVE, "CKM_SHA3_256_KEY_DERIVE"),
        (CKM.CKM_SHA3_384_KEY_DERIVE, "CKM_SHA3_384_KEY_DERIVE"),
        (CKM.CKM_SHA3_512_KEY_DERIVE, "CKM_SHA3_512_KEY_DERIVE"),
        (CKM.CKM_SHAKE_128_KEY_DERIVE, "CKM_SHAKE_128_KEY_DERIVE"),
        (CKM.CKM_SHAKE_256_KEY_DERIVE, "CKM_SHAKE_256_KEY_DERIVE"),
    ];

    public static TheoryData<CKM, string> AliasedMechanisms
    {
        get
        {
            var data = new TheoryData<CKM, string>();
            foreach ((CKM value, string preferred) in Aliases) data.Add(value, preferred);
            return data;
        }
    }

    [Fact]
    public void EveryAliasedCkmValue_HasAPreferredName()
    {
        var expected = Aliases.Select(alias => alias.Value).ToHashSet();
        var aliased = Enum.GetNames<CKM>()
            .GroupBy(name => Enum.Parse<CKM>(name))
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToHashSet();
        Assert.Equal(aliased.Order(), expected.Order());
    }

    [Theory]
    [MemberData(nameof(AliasedMechanisms))]
    public void AliasedValue_RendersItsPreferredName(CKM mechanism, string preferred)
    {
        Assert.Equal(preferred, MechanismNames.Of(mechanism));

        PolicyCatalogue catalogue = BuildCatalogue();
        var withAlias = new PolicyCatalogue
        {
            AllowedMechanisms = new Dictionary<CKM, MechanismRule>
            {
                [mechanism] = new(CryptoOperations.Encrypt, CryptoOperations.None, null, "Allowed."),
            }.ToFrozenDictionary(),
            AllowedVendorMechanisms = catalogue.AllowedVendorMechanisms,
            AllowedHashes = catalogue.AllowedHashes,
            AllowedCurves = catalogue.AllowedCurves,
            AllowedKdfs = catalogue.AllowedKdfs,
            AllowedKeyAgreementKeyTypes = catalogue.AllowedKeyAgreementKeyTypes,
            AllowedKdfPrfs = catalogue.AllowedKdfPrfs,
            RsaKeyGeneration = catalogue.RsaKeyGeneration,
            KeyTemplate = catalogue.KeyTemplate,
            SecretExport = catalogue.SecretExport,
            DocumentedRefusedMechanisms = new Dictionary<CKM, DocumentedRefusal>
            {
                [mechanism] = new("Refused.", null),
            }.ToFrozenDictionary(),
            DocumentedRefusedHashes = catalogue.DocumentedRefusedHashes,
            DocumentedRefusedCurves = catalogue.DocumentedRefusedCurves,
            DocumentedRefusedKdfs = catalogue.DocumentedRefusedKdfs,
            DocumentedRefusedKeyAgreementKeyTypes = catalogue.DocumentedRefusedKeyAgreementKeyTypes,
            DocumentedRefusedPrfs = catalogue.DocumentedRefusedPrfs,
        };
        string markdown = PolicyCatalogueMarkdown.Render(withAlias, "Recommended");

        Assert.Contains($"| `{preferred}` | Encrypt |", markdown);
        Assert.Contains($"| `{preferred}` | Refused. |", markdown);
        foreach (string other in Enum.GetNames<CKM>().Where(n => Enum.Parse<CKM>(n) == mechanism && n != preferred))
            Assert.DoesNotContain($"`{other}`", markdown);
    }

    // --- MechanismFamily classifier ---

    [Theory]
    [InlineData(CKM.CKM_AES_GCM, "AES")]
    [InlineData(CKM.CKM_AES_CMAC, "AES")]
    [InlineData(CKM.CKM_CHACHA20_POLY1305, "ChaCha20 / Salsa20")]
    [InlineData(CKM.CKM_SALSA20, "ChaCha20 / Salsa20")]
    [InlineData(CKM.CKM_DES3_CBC, "DES / TDEA")]
    [InlineData(CKM.CKM_SHA256, "Digest / HMAC")]
    [InlineData(CKM.CKM_SHA256_HMAC, "Digest / HMAC")]
    [InlineData(CKM.CKM_GENERIC_SECRET_KEY_GEN, "Digest / HMAC")]
    [InlineData(CKM.CKM_SHA256_RSA_PKCS_PSS, "RSA signature")]
    [InlineData(CKM.CKM_SHA256_RSA_PKCS, "RSA signature")]
    [InlineData(CKM.CKM_RSA_PKCS_OAEP, "RSA encryption")]
    [InlineData(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, "RSA key generation")]
    [InlineData(CKM.CKM_RSA_X9_31_KEY_PAIR_GEN, "RSA key generation")]
    [InlineData(CKM.CKM_DSA_KEY_PAIR_GEN, "DSA")]
    [InlineData(CKM.CKM_ECDSA, "EC")]
    [InlineData(CKM.CKM_EDDSA, "EC")]
    [InlineData(CKM.CKM_EC_KEY_PAIR_GEN, "EC")]
    [InlineData(CKM.CKM_ECDH1_DERIVE, "EC")]
    [InlineData(CKM.CKM_ML_KEM, "Post-quantum")]
    [InlineData(CKM.CKM_ML_DSA_KEY_PAIR_GEN, "Post-quantum")]
    [InlineData(CKM.CKM_SLH_DSA, "Post-quantum")]
    [InlineData(CKM.CKM_SP800_108_COUNTER_KDF, "KDF")]
    [InlineData(CKM.CKM_HKDF_DERIVE, "KDF")]
    [InlineData(CKM.CKM_PKCS5_PBKD2, "KDF")]
    [InlineData(CKM.CKM_SHA256_KEY_DERIVATION, "Key derivation")]
    [InlineData(CKM.CKM_IKE_PRF_DERIVE, "Key derivation")]
    [InlineData(CKM.CKM_RC4, "Legacy ciphers")]
    [InlineData(CKM.CKM_SKIPJACK_KEY_GEN, "Legacy ciphers")]
    // GOST mechanisms must all group together, even the ones whose own name embeds a digest-looking
    // token: CKM_GOSTR3410_WITH_GOSTR3411 and CKM_GOSTR3411_HMAC contain "GOSTR3411", and CKM_GOSTR3411
    // (the bare hash) IS that token, yet none of them are a generic SHA-family digest/HMAC.
    [InlineData(CKM.CKM_GOSTR3410, "Legacy ciphers")]
    [InlineData(CKM.CKM_GOSTR3410_WITH_GOSTR3411, "Legacy ciphers")]
    [InlineData(CKM.CKM_GOSTR3411, "Legacy ciphers")]
    [InlineData(CKM.CKM_GOSTR3411_HMAC, "Legacy ciphers")]
    [InlineData(CKM.CKM_GOST28147_ECB, "Legacy ciphers")]
    public void MechanismFamily_ClassifiesKnownMechanisms(CKM mechanism, string expectedFamily)
        => Assert.Equal(expectedFamily, PolicyCatalogueMarkdown.MechanismFamily(mechanism));
}
