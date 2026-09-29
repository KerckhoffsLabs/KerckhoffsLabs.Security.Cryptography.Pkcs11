using System.Collections.Frozen;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

#pragma warning disable KLPKCS11007, KLPKCS11009 // weak curves and mechanisms are used deliberately as denial fixtures here

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>
/// Exercises <see cref="CatalogueEvaluator"/> against a small, hand-built <see cref="PolicyCatalogue"/> —
/// independent of the real FipsOnly/SecureOnly catalogues — so these tests pin the shared evaluation and
/// denial-wording rules rather than any one policy's content.
/// </summary>
public sealed class CatalogueEvaluatorTests
{
    private const string PolicyName = "TestPolicy";

    // A mechanism allowed outright for Encrypt/Decrypt.
    private const CKM AllowedMechanism = CKM.CKM_AES_GCM;

    // A mechanism allowed only as SP 800-131A "legacy use" for Verify.
    private const CKM LegacyOnlyMechanism = CKM.CKM_DES3_CBC;

    // A mechanism allowed for Encrypt, but whose parameter check always denies.
    private const CKM ParamCheckedMechanism = CKM.CKM_RSA_PKCS_OAEP;

    // A mechanism that is both allowed (for Sign) and carries a documented refusal. The documented
    // refusal is reachable only when documentation does NOT enforce, and never for wording either: an
    // Allow (Sign) and the operation-restricted wording (any other operation) must both win over it.
    private const CKM DualMechanism = CKM.CKM_RSA_PKCS;

    // A mechanism with no allow-list entry, but a documented refusal with an alternative.
    private const CKM DocumentedRefusedMechanism = CKM.CKM_MD5;

    // A mechanism with no allow-list entry, but a documented refusal with no alternative.
    private const CKM DocumentedRefusedMechanismNoAlternative = CKM.CKM_RC4;

    // A mechanism with no allow-list entry and no documented refusal.
    private const CKM UnlistedMechanism = CKM.CKM_SHA_1;

    // An RSA key-generation mechanism on the allow list, routed through the catalogue's Rules.
    private const CKM RsaKeyGenMechanism = CKM.CKM_RSA_PKCS_KEY_PAIR_GEN;

    // Not an RSA key-pair-generation mechanism at all, but the catalogue allows it for GenerateKeyPair
    // anyway (it's a perfectly good EC key-gen mechanism) — proves the RSA-mechanism-type guard is an
    // evaluator-level check, not something a catalogue can accidentally bypass.
    private const CKM NonRsaKeyGenMechanism = CKM.CKM_EC_KEY_PAIR_GEN;

    private const ulong VendorMechanism = 0x8000_1234UL;

    private static readonly PolicyDecision ParamCheckDenial = PolicyDecision.Deny("param check denial");

    private static PolicyCatalogue BuildCatalogue() => new()
    {
        AllowedMechanisms = new Dictionary<CKM, MechanismRule>
        {
            [AllowedMechanism] = new(CryptoOperations.Encrypt | CryptoOperations.Decrypt, CryptoOperations.None, null, "TEST-ALLOWED"),
            [LegacyOnlyMechanism] = new(CryptoOperations.None, CryptoOperations.Verify, null, "TEST-LEGACY"),
            [ParamCheckedMechanism] = new(CryptoOperations.Encrypt, CryptoOperations.None, (_, _) => ParamCheckDenial, "TEST-PARAM"),
            [DualMechanism] = new(CryptoOperations.Sign, CryptoOperations.None, null, "TEST-DUAL"),
            [RsaKeyGenMechanism] = new(CryptoOperations.GenerateKeyPair, CryptoOperations.None, null, "TEST-RSA-KEYGEN"),
            [NonRsaKeyGenMechanism] = new(CryptoOperations.GenerateKeyPair, CryptoOperations.None, null, "TEST-EC-KEYGEN"),
        }.ToFrozenDictionary(),
        AllowedVendorMechanisms = new Dictionary<ulong, MechanismRule>
        {
            [VendorMechanism] = new(CryptoOperations.Encrypt, CryptoOperations.None, null, "TEST-VENDOR"),
        }.ToFrozenDictionary(),
        AllowedHashes = new Dictionary<string, AllowedHash>(StringComparer.Ordinal)
        {
            ["SHA256"] = new(CryptoOperations.Sign | CryptoOperations.Verify, "TEST-HASH-ALLOWED"),
        }.ToFrozenDictionary(StringComparer.Ordinal),
        AllowedCurves = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["1.2.3.4"] = "TEST-CURVE-ALLOWED",
        }.ToFrozenDictionary(StringComparer.Ordinal),
        AllowedKdfs = new Dictionary<CKD, string>
        {
            [CKD.CKD_SHA256_KDF] = "TEST-KDF-ALLOWED",
        }.ToFrozenDictionary(),
        AllowedKeyAgreementKeyTypes = new Dictionary<CKK, string>
        {
            [CKK.CKK_EC] = "TEST-KEYTYPE-ALLOWED",
        }.ToFrozenDictionary(),
        Rules = new PolicyRules(
            RsaKeyGeneration: r => r.ModulusBits < 1024
                ? PolicyDecision.Deny("RSA modulus too small")
                : PolicyDecision.Allow,
            KeyTemplate: _ => PolicyDecision.Deny("template rule fired"),
            KeyMaterialExport: _ => PolicyDecision.Deny("export rule fired"),
            RsaKeyGenerationRationale: "TEST-RSA-KEYGEN-RULE",
            KeyTemplateRationale: "TEST-TEMPLATE-RULE",
            KeyMaterialExportRationale: "TEST-EXPORT-RULE"),
        DocumentedRefusedMechanisms = new Dictionary<CKM, DocumentedRefusal>
        {
            [DocumentedRefusedMechanism] = new("it is cryptographically broken", "SHA256"),
            [DocumentedRefusedMechanismNoAlternative] = new("it is a broken stream cipher.", null),
            [DualMechanism] = new("key transport is refused", null),
        }.ToFrozenDictionary(),
        DocumentedRefusedHashes = new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal)
        {
            ["MD5"] = new("broken hash", "SHA256"),
        }.ToFrozenDictionary(StringComparer.Ordinal),
        DocumentedRefusedCurves = new Dictionary<string, DocumentedRefusal>(StringComparer.Ordinal)
        {
            ["1.2.3.9"] = new("too weak", null),
        }.ToFrozenDictionary(StringComparer.Ordinal),
        DocumentedRefusedKdfs = new Dictionary<CKD, DocumentedRefusal>
        {
            [CKD.CKD_NULL] = new("applies no KDF at all", "CKD_SHA256_KDF"),
        }.ToFrozenDictionary(),
        DocumentedRefusedKeyAgreementKeyTypes = new Dictionary<CKK, DocumentedRefusal>
        {
            [CKK.CKK_EC_MONTGOMERY] = new("Montgomery keys are refused.", "a CKK_EC key"),
        }.ToFrozenDictionary(),
        DocumentedRefusedPrfs = FrozenDictionary<string, DocumentedRefusal>.Empty,
        AllowedKdfPrfs = FrozenDictionary<string, FrozenSet<string>>.Empty,
    };

    // Stands in for a policy's extension hint (SecureOnly passes its WithAllowedMechanism sentence).
    private const string Hint = "TEST-HINT.";

    private static PolicyDecision Evaluate(PolicyRequest request, string? extensionHint = null)
        => CatalogueEvaluator.Evaluate(BuildCatalogue(), PolicyName, extensionHint, request);

    // --- Mechanisms ---

    [Fact]
    public void AllowedOperation_IsAllowed()
    {
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(AllowedMechanism), CryptoOperation.Encrypt));
        Assert.True(d.IsAllowed);
    }

    // AllowedMechanism only covers Encrypt/Decrypt. It IS on the allow-list, so this must not read as
    // "not reviewed" — and, since it was deliberately restricted rather than merely unreviewed, it must
    // never append the extension hint, whether or not the policy supplies one.
    [Theory]
    [InlineData(null)]
    [InlineData(Hint)]
    public void AllowedMechanism_RequestedForANonPermittedOperation_UsesOperationRestrictedWording(string? extensionHint)
    {
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(AllowedMechanism), CryptoOperation.Sign), extensionHint);
        Assert.False(d.IsAllowed);
        Assert.Equal($"{AllowedMechanism} is allowed under {PolicyName} only for Encrypt, Decrypt; Sign is not. TEST-ALLOWED", d.Reason);
    }

    [Fact]
    public void LegacyOperation_IsAllowed()
    {
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(LegacyOnlyMechanism), CryptoOperation.Verify));
        Assert.True(d.IsAllowed);
    }

    [Fact]
    public void LegacyMechanism_OutsideItsLegacyOperation_UsesOperationRestrictedWording()
    {
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(LegacyOnlyMechanism), CryptoOperation.Sign));
        Assert.False(d.IsAllowed);
        Assert.Equal($"{LegacyOnlyMechanism} is allowed under {PolicyName} only for Verify; Sign is not. TEST-LEGACY", d.Reason);
    }

    [Fact]
    public void ParameterCheckDenial_Propagates()
    {
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(ParamCheckedMechanism), CryptoOperation.Encrypt));
        Assert.False(d.IsAllowed);
        Assert.Equal(ParamCheckDenial.Reason, d.Reason);
    }

    [Fact]
    public void DocumentedRefusedMechanism_IsDeniedWithReasonAndAlternative()
    {
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(DocumentedRefusedMechanism), CryptoOperation.Digest));
        Assert.False(d.IsAllowed);
        Assert.Equal($"{DocumentedRefusedMechanism} is not allowed: it is cryptographically broken Use SHA256.", d.Reason);
    }

    [Fact]
    public void DocumentedRefusedMechanism_WithoutAnAlternative_OmitsTheUseSentence()
    {
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(DocumentedRefusedMechanismNoAlternative), CryptoOperation.Encrypt));
        Assert.False(d.IsAllowed);
        Assert.Equal($"{DocumentedRefusedMechanismNoAlternative} is not allowed: it is a broken stream cipher.", d.Reason);
    }

    // DualMechanism carries a documented refusal (reachable only when documentation is read directly,
    // e.g. by the catalogue renderer) but it is also an allow-list entry — so a request for an operation it
    // doesn't cover must still get the operation-restricted wording, never the documented-refusal wording.
    [Fact]
    public void AllowedMechanism_WithADocumentedRefusalOnTheSameEntry_StillUsesOperationRestrictedWordingWhenMisused()
    {
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(DualMechanism), CryptoOperation.Encrypt));
        Assert.False(d.IsAllowed);
        Assert.Equal($"{DualMechanism} is allowed under {PolicyName} only for Sign; Encrypt is not. TEST-DUAL", d.Reason);
    }

    [Fact]
    public void UnlistedMechanism_IsDeniedWithNotReviewedWording_WithoutExtensionSuggestion()
    {
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(UnlistedMechanism), CryptoOperation.Digest), extensionHint: null);
        Assert.False(d.IsAllowed);
        Assert.Equal($"{UnlistedMechanism} is not on the {PolicyName} allow-list (not reviewed).", d.Reason);
    }

    [Fact]
    public void UnlistedMechanism_WithAnExtensionHint_AppendsIt()
    {
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(UnlistedMechanism), CryptoOperation.Digest), Hint);
        Assert.False(d.IsAllowed);
        Assert.Equal($"{UnlistedMechanism} is not on the {PolicyName} allow-list (not reviewed). {Hint}", d.Reason);
    }

    [Fact]
    public void UnlistedVendorMechanism_WithAnExtensionHint_AppendsIt()
    {
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(0x8000_9999UL), CryptoOperation.Sign), Hint);
        Assert.Equal($"vendor mechanism 0x80009999 is not on the {PolicyName} allow-list (not reviewed). {Hint}", d.Reason);
    }

    // The extension point adds mechanisms only: hashes, curves and key-agreement KDFs cannot be added
    // through it, so their "not reviewed" denials must never point at it.
    [Fact]
    public void UnlistedHashCurveAndKdf_NeverCarryTheExtensionHint()
    {
        PolicyDecision hash = Evaluate(new HashUseRequest(new HashAlgorithmName("SHA384"), CryptoOperation.Sign), Hint);
        PolicyDecision curve = Evaluate(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP192), Hint);
        PolicyDecision kdf = Evaluate(new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_SHA1_KDF), Hint);

        Assert.Equal($"SHA384 is not on the {PolicyName} allow-list (not reviewed).", hash.Reason);
        Assert.EndsWith($"is not on the {PolicyName} allow-list (not reviewed).", curve.Reason, StringComparison.Ordinal);
        Assert.Equal($"CKD_SHA1_KDF is not on the {PolicyName} allow-list (not reviewed).", kdf.Reason);
    }

    // CKM has aliases (two names for one value); denials name the current PKCS#11 v3 name, whichever
    // name the caller's source used.
    [Fact]
    public void AliasedMechanism_IsNamedByItsPreferredName()
    {
        PolicyDecision unlisted = Evaluate(new MechanismUseRequest(new Mechanism(CKM.CKM_SHA3_256_KEY_DERIVATION), CryptoOperation.Derive));
        Assert.StartsWith("CKM_SHA3_256_KEY_DERIVE is not on", unlisted.Reason, StringComparison.Ordinal);

        PolicyDecision restricted = Evaluate(new MechanismUseRequest(new Mechanism(CKM.CKM_ECDSA_KEY_PAIR_GEN), CryptoOperation.Sign));
        Assert.StartsWith($"CKM_EC_KEY_PAIR_GEN is allowed under {PolicyName} only for GenerateKeyPair;", restricted.Reason, StringComparison.Ordinal);
    }

    public static bool IsUnix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    // CK_ULONG is 64 bits on Unix, so a mechanism type can exceed CKM's 32-bit range. Such a value is a
    // vendor-range value: denied (never an OverflowException from a checked cast to CKM), and allowed only
    // through AllowedVendorMechanisms.
    [Fact(SkipUnless = nameof(IsUnix), Skip = "Requires a 64-bit CK_ULONG")]
    public void MechanismValueAbove32Bits_IsTreatedAsAVendorValue()
    {
        const ulong wide = 0x1_0000_0001UL;
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(wide), CryptoOperation.Encrypt), Hint);
        Assert.False(d.IsAllowed);
        Assert.Equal($"vendor mechanism 0x100000001 is not on the {PolicyName} allow-list (not reviewed). {Hint}", d.Reason);
    }

    [Fact]
    public void VendorMechanism_IsAllowedOnlyViaAllowedVendorMechanisms()
    {
        PolicyDecision allowed = Evaluate(new MechanismUseRequest(new Mechanism(VendorMechanism), CryptoOperation.Encrypt));
        Assert.True(allowed.IsAllowed);

        // Same raw value, but an operation the vendor entry doesn't cover: still denied, with the
        // operation-restricted wording (it IS on the vendor allow-list), and the standard (non-vendor)
        // table must not have been consulted for it.
        PolicyDecision denied = Evaluate(new MechanismUseRequest(new Mechanism(VendorMechanism), CryptoOperation.Sign));
        Assert.False(denied.IsAllowed);
        Assert.Equal($"vendor mechanism 0x{VendorMechanism:X} is allowed under {PolicyName} only for Encrypt; Sign is not. TEST-VENDOR", denied.Reason);
    }

    [Fact]
    public void UnlistedVendorValue_IsDenied()
    {
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(0xFFFF_FFFFUL), CryptoOperation.Encrypt));
        Assert.False(d.IsAllowed);
    }

    [Fact]
    public void AllowedMechanism_WithADocumentedRefusalOnTheSameEntry_StillYieldsAllow()
    {
        // DualMechanism is both allowed (for Sign) and carries a documented refusal. Documentation must
        // never override an actual allow-list match. Only reachable in this synthetic catalogue.
        PolicyDecision d = Evaluate(new MechanismUseRequest(new Mechanism(DualMechanism), CryptoOperation.Sign));
        Assert.True(d.IsAllowed);
    }

    // --- Hashes: same two-step behaviour, plus the operation-restricted wording ---

    [Fact]
    public void AllowedHash_IsAllowed()
        => Assert.True(Evaluate(new HashUseRequest(new HashAlgorithmName("SHA256"), CryptoOperation.Sign)).IsAllowed);

    [Fact]
    public void AllowedHash_RequestedForANonPermittedOperation_UsesOperationRestrictedWording()
    {
        PolicyDecision d = Evaluate(new HashUseRequest(new HashAlgorithmName("SHA256"), CryptoOperation.Digest));
        Assert.False(d.IsAllowed);
        Assert.Equal($"SHA256 is allowed under {PolicyName} only for Sign, Verify; Digest is not. TEST-HASH-ALLOWED", d.Reason);
    }

    [Fact]
    public void DocumentedRefusedHash_IsDeniedWithReason()
    {
        PolicyDecision d = Evaluate(new HashUseRequest(new HashAlgorithmName("MD5"), CryptoOperation.Sign));
        Assert.False(d.IsAllowed);
        Assert.Equal("MD5 is not allowed: broken hash Use SHA256.", d.Reason);
    }

    [Fact]
    public void UnlistedHash_IsDeniedWithNotReviewedWording()
    {
        PolicyDecision d = Evaluate(new HashUseRequest(new HashAlgorithmName("SHA384"), CryptoOperation.Sign));
        Assert.False(d.IsAllowed);
        Assert.Equal($"SHA384 is not on the {PolicyName} allow-list (not reviewed).", d.Reason);
    }

    // --- Curves: same two-step behaviour, plus the no-OID case ---

    [Fact]
    public void AllowedCurve_IsAllowed()
        => Assert.True(Evaluate(new EcKeyGenerationRequest(Pkcs11ECCurve.CreateFromValue("1.2.3.4", null))).IsAllowed);

    [Fact]
    public void DocumentedRefusedCurve_IsDeniedWithReason()
    {
        PolicyDecision d = Evaluate(new EcKeyGenerationRequest(Pkcs11ECCurve.CreateFromValue("1.2.3.9", null)));
        Assert.False(d.IsAllowed);
        Assert.Contains("too weak", d.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void UnlistedCurve_IsDeniedWithNotReviewedWording()
    {
        PolicyDecision d = Evaluate(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP192));
        Assert.False(d.IsAllowed);
        Assert.Contains("not reviewed", d.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void CurveWithNoOid_IsDenied()
        => Assert.False(Evaluate(new EcKeyGenerationRequest(default)).IsAllowed);

    // --- KDFs: same two-step behaviour ---

    [Fact]
    public void AllowedKdf_IsAllowed()
        => Assert.True(Evaluate(new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_SHA256_KDF)).IsAllowed);

    [Fact]
    public void DocumentedRefusedKdf_IsDeniedWithReason()
    {
        PolicyDecision d = Evaluate(new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL));
        Assert.False(d.IsAllowed);
        Assert.Equal("CKD_NULL is not allowed: applies no KDF at all Use CKD_SHA256_KDF.", d.Reason);
    }

    [Fact]
    public void UnlistedKdf_IsDeniedWithNotReviewedWording()
    {
        PolicyDecision d = Evaluate(new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_SHA1_KDF));
        Assert.False(d.IsAllowed);
        Assert.Equal($"CKD_SHA1_KDF is not on the {PolicyName} allow-list (not reviewed).", d.Reason);
    }

    // --- Key-agreement key types: same two-step behaviour ---

    [Fact]
    public void AllowedKeyAgreementKeyType_IsAllowed()
        => Assert.True(Evaluate(new KeyAgreementKeyRequest(CKM.CKM_ECDH1_DERIVE, CKK.CKK_EC)).IsAllowed);

    [Fact]
    public void DocumentedRefusedKeyAgreementKeyType_IsDeniedWithReason()
    {
        PolicyDecision d = Evaluate(new KeyAgreementKeyRequest(CKM.CKM_ECDH1_DERIVE, CKK.CKK_EC_MONTGOMERY));
        Assert.False(d.IsAllowed);
        Assert.Equal("Key agreement with a CKK_EC_MONTGOMERY key is not allowed: Montgomery keys are refused. Use a CKK_EC key.", d.Reason);
    }

    [Fact]
    public void UnlistedKeyAgreementKeyType_IsDeniedWithNotReviewedWording()
    {
        PolicyDecision d = Evaluate(new KeyAgreementKeyRequest(CKM.CKM_ECDH1_DERIVE, CKK.CKK_DH), Hint);
        Assert.False(d.IsAllowed);
        Assert.Equal($"Key agreement with a CKK_DH key is not on the {PolicyName} allow-list (not reviewed).", d.Reason);
    }

    // --- Rules (RSA key generation, key template, key material export) ---

    [Fact]
    public void RsaKeyGeneration_OnAnAllowedMechanism_RoutesThroughTheRules()
    {
        Assert.False(Evaluate(new RsaKeyGenerationRequest(RsaKeyGenMechanism, 512)).IsAllowed);
        Assert.True(Evaluate(new RsaKeyGenerationRequest(RsaKeyGenMechanism, 2048)).IsAllowed);
    }

    [Fact]
    public void RsaKeyGeneration_OnAMechanismNotOnTheAllowList_IsDeniedWithoutConsultingTheRules()
        => Assert.False(Evaluate(new RsaKeyGenerationRequest(CKM.CKM_RSA_X9_31_KEY_PAIR_GEN, 4096)).IsAllowed);

    // The mechanism check is the evaluator's, not the catalogue's: NonRsaKeyGenMechanism IS allowed by
    // this catalogue for GenerateKeyPair (see BuildCatalogue), yet RsaKeyGenerationRequest still refuses
    // it, because CKM_EC_KEY_PAIR_GEN is not one of the two mechanisms PKCS#11 defines for RSA key-pair
    // generation. This must hold for any catalogue.
    [Fact]
    public void RsaKeyGeneration_OnANonRsaMechanism_IsDeniedEvenWhenTheCatalogueAllowsItForGenerateKeyPair()
    {
        PolicyDecision d = Evaluate(new RsaKeyGenerationRequest(NonRsaKeyGenMechanism, 4096));
        Assert.False(d.IsAllowed);
        Assert.Contains("not an RSA key-pair-generation mechanism", d.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void KeyTemplate_AlwaysRoutesThroughTheRules()
    {
        PolicyDecision d = Evaluate(new KeyTemplateRequest(null, []));
        Assert.False(d.IsAllowed);
        Assert.Equal("template rule fired", d.Reason);
    }

    [Fact]
    public void KeyMaterialExport_AlwaysRoutesThroughTheRules()
    {
        PolicyDecision d = Evaluate(new KeyMaterialExportRequest(KeyMaterialExportKind.KdfOutput));
        Assert.False(d.IsAllowed);
        Assert.Equal("export rule fired", d.Reason);
    }

    // --- Closed request hierarchy ---

    [Fact]
    public void UnrecognizedRequestKind_IsDenied()
        => Assert.False(Evaluate(new UnrecognizedPolicyRequest()).IsAllowed);
}
