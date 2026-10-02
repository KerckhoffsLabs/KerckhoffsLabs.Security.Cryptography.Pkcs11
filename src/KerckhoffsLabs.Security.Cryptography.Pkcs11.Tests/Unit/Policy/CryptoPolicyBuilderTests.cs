using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.BuiltIn;

#pragma warning disable KLPKCS11009 // legacy mechanisms are the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

public sealed class CryptoPolicyBuilderTests
{
    private static bool Allowed(ComposedCryptoPolicy p, Mechanism m, CryptoOperation op) => p.Evaluate(new MechanismUseRequest(m, op)).IsAllowed;
    private static Mechanism Oaep(CKM hash) => new(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(hash, CKG.CKG_MGF1_SHA256));

    [Fact]
    public void EmptyBuilder_DeniesEveryMechanism_AndAppliesTheSecureDefaults()
    {
        ComposedCryptoPolicy p = new CryptoPolicyBuilder("Empty").Build();
        Assert.Equal("Empty", p.Name);
        Assert.True(p.AllowsOverride);
        Assert.False(Allowed(p, new Mechanism(CKM.CKM_AES_GCM), CryptoOperation.Encrypt));
        Assert.False(p.Evaluate(new SecretExportRequest(SecretExportKind.KdfOutput)).IsAllowed);
    }

    [Fact]
    public void AllowMechanism_AllowsExactlyTheGivenOperations()
    {
        ComposedCryptoPolicy p = new CryptoPolicyBuilder("App")
            .AllowMechanism(CKM.CKM_AES_GCM, [CryptoOperation.Encrypt, CryptoOperation.Decrypt], "AEAD.")
            .Build();
        Assert.True(Allowed(p, new Mechanism(CKM.CKM_AES_GCM), CryptoOperation.Decrypt));
        Assert.Equal("CKM_AES_GCM is allowed under App only for Encrypt, Decrypt; Sign is not. AEAD.",
            p.Evaluate(new MechanismUseRequest(new Mechanism(CKM.CKM_AES_GCM), CryptoOperation.Sign)).Reason);
    }

    [Fact]
    public void WideningACheckedEntry_KeepsItsCheck_AndADifferentCheckThrows()
    {
        MechanismCheck sha256Only = MechanismChecks.OaepHash([CKM.CKM_SHA256]);
        CryptoPolicyBuilder b = new CryptoPolicyBuilder("App")
            .AllowMechanism(CKM.CKM_RSA_PKCS_OAEP, [CryptoOperation.Encrypt], "OAEP.", sha256Only)
            .AllowMechanism(CKM.CKM_RSA_PKCS_OAEP, [CryptoOperation.Wrap], "OAEP, widened.");
        ComposedCryptoPolicy p = b.Build();
        Assert.False(Allowed(p, Oaep(CKM.CKM_SHA_1), CryptoOperation.Wrap));
        Assert.True(Allowed(p, Oaep(CKM.CKM_SHA256), CryptoOperation.Wrap));

        Assert.Throws<ArgumentException>(() =>
            b.AllowMechanism(CKM.CKM_RSA_PKCS_OAEP, [CryptoOperation.Encrypt], "x", MechanismChecks.OaepHash([CKM.CKM_SHA384])));
        b.AllowMechanism(CKM.CKM_RSA_PKCS_OAEP, [CryptoOperation.Decrypt], "same check", sha256Only); // the same instance is fine
    }

    [Fact]
    public void BuiltPolicies_AreIsolatedFromLaterBuilderChanges()
    {
        CryptoPolicyBuilder b = new CryptoPolicyBuilder("App").AllowMechanism(CKM.CKM_AES_GCM, [CryptoOperation.Encrypt], "AEAD.");
        ComposedCryptoPolicy first = b.Build();
        b.RemoveMechanism(CKM.CKM_AES_GCM);
        Assert.True(Allowed(first, new Mechanism(CKM.CKM_AES_GCM), CryptoOperation.Encrypt));
        Assert.False(Allowed(b.Build(), new Mechanism(CKM.CKM_AES_GCM), CryptoOperation.Encrypt));
    }

    [Theory]
    [InlineData("Recommended")]
    [InlineData("NistApproved")]
    [InlineData("recommended")]
    [InlineData(" NistApproved ")]
    public void ReservedNames_AreRejected(string name) => Assert.Throws<ArgumentException>(() => new CryptoPolicyBuilder(name));

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void BlankNames_AreRejected(string name) => Assert.Throws<ArgumentException>(() => new CryptoPolicyBuilder(name));

    [Fact]
    public void VendorMechanisms_CanBeAllowedAndRemoved()
    {
        var vendor = (CKM)0x80001234UL;
        CryptoPolicyBuilder b = new CryptoPolicyBuilder("App").AllowMechanism(vendor, [CryptoOperation.Sign], "Reviewed.");
        Assert.True(Allowed(b.Build(), new Mechanism(vendor), CryptoOperation.Sign));
        Assert.False(Allowed(b.RemoveMechanism(vendor).Build(), new Mechanism(vendor), CryptoOperation.Sign));
    }

    [Fact]
    public void LegacyUse_AllowsOnlyItsOperations()
    {
        ComposedCryptoPolicy p = new CryptoPolicyBuilder("App")
            .AllowMechanismForLegacyUse(CKM.CKM_DES3_CBC, [CryptoOperation.Decrypt], "Old archives.")
            .Build();
        Assert.True(Allowed(p, new Mechanism(CKM.CKM_DES3_CBC), CryptoOperation.Decrypt));
        Assert.False(Allowed(p, new Mechanism(CKM.CKM_DES3_CBC), CryptoOperation.Encrypt));
    }

    [Fact]
    public void AllowsOverride_CanBeSet() =>
        Assert.False(new CryptoPolicyBuilder("App").AllowsOverride(false).Build().AllowsOverride);

    [Fact]
    public void EmptyOperations_Throw() =>
        Assert.Throws<ArgumentException>(() => new CryptoPolicyBuilder("App").AllowMechanism(CKM.CKM_AES_GCM, [], "x"));

    [Fact]
    public void ARsaRule_Replaces_TheDefault()
    {
        ComposedCryptoPolicy p = new CryptoPolicyBuilder("App")
            .AllowMechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, [CryptoOperation.GenerateKeyPair], "RSA.")
            .WithRsaKeyGenerationRule(RsaKeyGenerationRule.Minimum(3072))
            .Build();
        Assert.False(p.Evaluate(new RsaKeyGenerationRequest(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, 2048)).IsAllowed);
        Assert.True(p.Evaluate(new RsaKeyGenerationRequest(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, 3072)).IsAllowed);
    }

    [Fact]
    public void HashesCurvesKdfsAndKeyTypes_CanBeAllowedAndRemoved()
    {
        ComposedCryptoPolicy p = new CryptoPolicyBuilder("App")
            .AllowHash(HashAlgorithmName.SHA256, [CryptoOperation.Sign], "SHA-2.")
            .AllowCurve(Pkcs11ECCurve.NamedCurves.NistP256, "P-256.")
            .AllowKeyAgreementKdf(CKD.CKD_SHA256_KDF, "X9.63.")
            .AllowKeyAgreementKeyType(CKK.CKK_EC, "ECDH.")
            .Build();
        Assert.True(p.Evaluate(new HashUseRequest(HashAlgorithmName.SHA256, CryptoOperation.Sign)).IsAllowed);
        Assert.True(p.Evaluate(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP256)).IsAllowed);
        Assert.True(p.Evaluate(new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_SHA256_KDF)).IsAllowed);
        Assert.True(p.Evaluate(new KeyAgreementKeyRequest(CKM.CKM_ECDH1_DERIVE, CKK.CKK_EC)).IsAllowed);

        ComposedCryptoPolicy tightened = p.ToBuilder("App")
            .RemoveHash(HashAlgorithmName.SHA256)
            .RemoveCurve(Pkcs11ECCurve.NamedCurves.NistP256)
            .RemoveKeyAgreementKdf(CKD.CKD_SHA256_KDF)
            .RemoveKeyAgreementKeyType(CKK.CKK_EC)
            .Build();
        Assert.False(tightened.Evaluate(new HashUseRequest(HashAlgorithmName.SHA256, CryptoOperation.Sign)).IsAllowed);
        Assert.False(tightened.Evaluate(new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP256)).IsAllowed);
        Assert.False(tightened.Evaluate(new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_SHA256_KDF)).IsAllowed);
        Assert.False(tightened.Evaluate(new KeyAgreementKeyRequest(CKM.CKM_ECDH1_DERIVE, CKK.CKK_EC)).IsAllowed);
    }

    // Review focus 1.
    [Fact]
    public void WideningRecommendedOaep_KeepsItsHashCheck()
    {
        ComposedCryptoPolicy p = CryptoPolicy.Recommended.ToBuilder("App")
            .AllowMechanism(CKM.CKM_RSA_PKCS_OAEP, [CryptoOperation.Sign], "Test widening.")
            .Build();
        Assert.False(Allowed(p, Oaep(CKM.CKM_SHA_1), CryptoOperation.Sign));
        Assert.True(Allowed(p, Oaep(CKM.CKM_SHA256), CryptoOperation.Sign));
        Assert.False(Allowed(p, Oaep(CKM.CKM_SHA_1), CryptoOperation.Encrypt));
    }

    // Review focus 2.
    [Theory]
    [InlineData("Recommended")]
    [InlineData("NistApproved")]
    [InlineData("recommended")]
    [InlineData(" NistApproved ")]
    public void ToBuilder_RejectsReservedNames(string name) =>
        Assert.Throws<ArgumentException>(() => CryptoPolicy.Recommended.ToBuilder(name));

    // Review focus 3.
    [Fact]
    public void FipsDerived_KeepsNoOverride_AndFipsWording()
    {
        ComposedCryptoPolicy p = CryptoPolicy.NistApproved.ToBuilder("FipsPlus").Build();
        Assert.Equal("FipsPlus", p.Name);
        Assert.False(p.AllowsOverride);
        Assert.StartsWith("SP 800-56B Rev.2",
            p.Evaluate(new MechanismUseRequest(new Mechanism(CKM.CKM_RSA_PKCS_OAEP), CryptoOperation.Encrypt)).Reason);
        Assert.True(CryptoPolicy.NistApproved.ToBuilder("App").AllowsOverride(true).Build().AllowsOverride);
    }

    // Review focus 4.
    [Fact]
    public void SecondGenerationCopies_CarryEveryRuleAndRefusal()
    {
        ComposedCryptoPolicy first = CryptoPolicy.Recommended.ToBuilder("App").Build();
        ComposedCryptoPolicy second = first.ToBuilder("App2").Build();
        var des = new MechanismUseRequest(new Mechanism(CKM.CKM_DES_CBC), CryptoOperation.Decrypt);
        Assert.Equal(CryptoPolicy.Recommended.Evaluate(des).Reason, second.Evaluate(des).Reason);
        Assert.False(Allowed(second, Oaep(CKM.CKM_SHA_1), CryptoOperation.Encrypt));
        Assert.False(second.Evaluate(new RsaKeyGenerationRequest(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, 1024)).IsAllowed);
    }

    // Review focus 5.
    [Fact]
    public void UnlistedVendorMechanism_OnARecommendedCopy_GetsAHintNamingThatCopy()
    {
        var vendor = (CKM)0x80001234UL;
        ComposedCryptoPolicy p = CryptoPolicy.Recommended.ToBuilder("App").Build();

        string? reason = p.Evaluate(new MechanismUseRequest(new Mechanism(vendor), CryptoOperation.Sign)).Reason;

        Assert.EndsWith("add it with ToBuilder(...).AllowMechanism(...) on the App policy.", reason);
        Assert.DoesNotContain("CryptoPolicy.Recommended", reason);
    }

    [Fact]
    public void UnlistedVendorMechanism_OnRecommended_GetsTheBuiltInHint() =>
        Assert.EndsWith("add it with CryptoPolicy.Recommended.ToBuilder(...).AllowMechanism(...).",
            CryptoPolicy.Recommended.Evaluate(new MechanismUseRequest(new Mechanism((CKM)0x80001234UL), CryptoOperation.Sign)).Reason);

    [Fact]
    public void ExportRefusal_OnARecommendedCopy_NamesThatCopy()
    {
        ComposedCryptoPolicy p = CryptoPolicy.Recommended.ToBuilder("App").Build();

        string? reason = p.Evaluate(new SecretExportRequest(SecretExportKind.KdfOutput)).Reason;

        Assert.Contains("ToBuilder(...).AllowSecretExport(SecretExportKind.KdfOutput, reason) on the App policy.", reason);
        Assert.DoesNotContain("CryptoPolicy.Recommended", reason);
    }

    // A policy built from scratch gets the same guidance as one derived from Recommended: the on-token
    // alternative for the kind, and the opt-in on its own builder.
    [Theory]
    [InlineData(SecretExportKind.PasswordKdfOutput, "Pkcs11Workspace.GenerateKey with CKM_PKCS5_PBKD2")]
    [InlineData(SecretExportKind.EcdhSharedSecret, "Pkcs11Workspace.DeriveSharedSecretEcdh")]
    public void ExportRefusal_OnAPolicyBuiltFromScratch_NamesTheAlternativeAndTheOptIn(SecretExportKind kind, string alternative)
    {
        string? reason = new CryptoPolicyBuilder("App").Build().Evaluate(new SecretExportRequest(kind)).Reason;

        Assert.Contains(alternative, reason);
        Assert.Contains($"ToBuilder(...).AllowSecretExport(SecretExportKind.{kind}, reason) on the App policy.", reason);
    }

    // Hints name a built-in by the reference its catalogue carries, never by comparing policy names; a copy is
    // the caller's own policy and carries none.
    [Fact]
    public void BuiltIns_CarryTheirReference_AndCopiesDoNot()
    {
        Assert.Equal("CryptoPolicy.Recommended", CryptoPolicy.Recommended.Catalogue.BuiltInReference);
        Assert.Equal("CryptoPolicy.NistApproved", CryptoPolicy.NistApproved.Catalogue.BuiltInReference);
        Assert.Null(CryptoPolicy.Recommended.ToBuilder("App").Build().Catalogue.BuiltInReference);
        Assert.Null(CryptoPolicy.NistApproved.ToBuilder("App").Build().Catalogue.BuiltInReference);
        Assert.Null(new CryptoPolicyBuilder("App").Build().Catalogue.BuiltInReference);
    }

    [Fact]
    public void ExportRefusal_OnRecommended_NamesTheBuiltIn() =>
        Assert.Contains("CryptoPolicy.Recommended.ToBuilder(...).AllowSecretExport(SecretExportKind.KdfOutput, reason).",
            CryptoPolicy.Recommended.Evaluate(new SecretExportRequest(SecretExportKind.KdfOutput)).Reason);

    [Fact]
    public void DocumentedRefusals_OnARecommendedCopy_DoNotPointAtRecommended()
    {
        ComposedCryptoPolicy p = CryptoPolicy.Recommended.ToBuilder("App").Build();

        Assert.DoesNotContain("CryptoPolicy.Recommended",
            p.Evaluate(new MechanismUseRequest(new Mechanism(CKM.CKM_IKE2_PRF_PLUS_DERIVE), CryptoOperation.Derive)).Reason);
    }

    [Fact]
    public void ADocumentedRefusal_CanBeAllowedAfterReview()
    {
        ComposedCryptoPolicy p = CryptoPolicy.Recommended.ToBuilder("App")
            .AllowMechanism(CKM.CKM_DES_CBC, [CryptoOperation.Decrypt], "Legacy archive decryption only.")
            .Build();
        Assert.True(Allowed(p, new Mechanism(CKM.CKM_DES_CBC), CryptoOperation.Decrypt));
        Assert.False(Allowed(p, new Mechanism(CKM.CKM_DES_CBC), CryptoOperation.Encrypt));
        Assert.False(Allowed(CryptoPolicy.Recommended, new Mechanism(CKM.CKM_DES_CBC), CryptoOperation.Decrypt));
    }

    [Fact]
    public void Remove_TightensADerivedPolicyOnly()
    {
        ComposedCryptoPolicy p = CryptoPolicy.Recommended.ToBuilder("App").RemoveMechanism(CKM.CKM_AES_CCM).Build();
        Assert.False(Allowed(p, new Mechanism(CKM.CKM_AES_CCM), CryptoOperation.Encrypt));
        Assert.True(Allowed(CryptoPolicy.Recommended, new Mechanism(CKM.CKM_AES_CCM), CryptoOperation.Encrypt));
    }

    // === Argument validation ===================================================

    // An undefined operation would otherwise shift into another operation's flag (1 << 32 wraps to 1 << 0).
    [Fact]
    public void UndefinedOperation_Throws()
    {
        Assert.Throws<ArgumentException>(() => new CryptoPolicyBuilder("App").AllowMechanism(CKM.CKM_AES_GCM, [(CryptoOperation)32], "x"));
        Assert.Throws<ArgumentException>(() =>
            new CryptoPolicyBuilder("App").AllowMechanism(CKM.CKM_AES_GCM, [CryptoOperation.Decrypt, (CryptoOperation)(-1)], "x"));
        Assert.Throws<ArgumentException>(() => new CryptoPolicyBuilder("App").AllowHash(HashAlgorithmName.SHA256, [(CryptoOperation)99], "x"));
    }

    [Fact]
    public void NullOperations_ThrowArgumentNullException() =>
        Assert.Throws<ArgumentNullException>(() => new CryptoPolicyBuilder("App").AllowMechanism(CKM.CKM_AES_GCM, null!, "x"));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void BlankRationale_Throws(string rationale)
    {
        Assert.Throws<ArgumentException>(() => new CryptoPolicyBuilder("App").AllowMechanism(CKM.CKM_AES_GCM, [CryptoOperation.Encrypt], rationale));
        Assert.Throws<ArgumentException>(() => new CryptoPolicyBuilder("App").AllowKeyAgreementKdf(CKD.CKD_SHA256_KDF, rationale));
    }

    [Fact]
    public void NullRationale_ThrowsArgumentNullException() =>
        Assert.Throws<ArgumentNullException>(() => new CryptoPolicyBuilder("App").AllowMechanism(CKM.CKM_AES_GCM, [CryptoOperation.Encrypt], null!));

    public static bool IsUnix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    [Fact(SkipUnless = nameof(IsUnix), Skip = "Requires a 64-bit CK_ULONG")]
    public void MechanismValueAbove32Bits_IsDeniedByDefault_AndAllowedOnceAllowed()
    {
        const CKM wide = (CKM)0x1_0000_0001UL;
        var mechanism = new Mechanism(wide);
        Assert.False(Allowed(CryptoPolicy.Recommended, mechanism, CryptoOperation.Sign));

        ComposedCryptoPolicy p = CryptoPolicy.Recommended.ToBuilder("App").AllowMechanism(wide, [CryptoOperation.Sign], "Reviewed.").Build();
        Assert.True(Allowed(p, mechanism, CryptoOperation.Sign));
        Assert.False(Allowed(p, mechanism, CryptoOperation.Verify));
        Assert.True(p.Catalogue.AllowedVendorMechanisms.ContainsKey((ulong)wide));
    }

    [Fact]
    public void WideningEcdh_KeepsDerive_AndItsParameterCheck()
    {
        ComposedCryptoPolicy p = CryptoPolicy.Recommended.ToBuilder("App")
            .AllowMechanism(CKM.CKM_ECDH1_DERIVE, [CryptoOperation.Encrypt], "Test widening.")
            .Build();
        var ecdh = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, [0x04, 0x01, 0x04]));
        Assert.True(Allowed(p, ecdh, CryptoOperation.Derive));
        Assert.True(Allowed(p, ecdh, CryptoOperation.Encrypt));
        Assert.False(Allowed(p, new Mechanism(CKM.CKM_ECDH1_DERIVE), CryptoOperation.Encrypt));
    }

    // Without Ecdh1DeriveParams, ECDH with raw parameter bytes never raises a KeyAgreementKdfRequest, so the
    // policy's KDF allow-list would silently not apply.
    [Theory]
    [InlineData(CKM.CKM_ECDH1_DERIVE)]
    [InlineData(CKM.CKM_ECDH1_COFACTOR_DERIVE)]
    public void Ecdh_WithoutItsParameterCheck_IsRefused(CKM ecdh)
    {
        Assert.Throws<ArgumentException>(() => new CryptoPolicyBuilder("App").AllowMechanism(ecdh, [CryptoOperation.Derive], "ECDH."));
        ComposedCryptoPolicy p = new CryptoPolicyBuilder("App")
            .AllowMechanism(ecdh, [CryptoOperation.Derive], "ECDH.", MechanismChecks.Ecdh1DeriveParams())
            .AllowKeyAgreementKdf(CKD.CKD_SHA256_KDF, "X9.63.")
            .Build();
        Assert.False(Allowed(p, new Mechanism(ecdh, new byte[24]), CryptoOperation.Derive));
    }

    // === Value equality, removal wording, names, hashes =========================

    [Fact]
    public void EqualChecksFromTheSameFactory_DoNotConflict_DifferentOnesDo()
    {
        CryptoPolicyBuilder b = new CryptoPolicyBuilder("App")
            .AllowMechanism(CKM.CKM_AES_GCM, [CryptoOperation.Encrypt], "AEAD.", MechanismChecks.GcmTagLength(96))
            .AllowMechanism(CKM.CKM_AES_GCM, [CryptoOperation.Decrypt], "AEAD.", MechanismChecks.GcmTagLength(96));
        Assert.True(Allowed(b.Build(), new Mechanism(CKM.CKM_AES_GCM), CryptoOperation.Decrypt));
        Assert.Throws<ArgumentException>(() =>
            b.AllowMechanism(CKM.CKM_AES_GCM, [CryptoOperation.Wrap], "AEAD.", MechanismChecks.GcmTagLength(104)));
        Assert.Throws<ArgumentException>(() =>
            b.AllowMechanismForLegacyUse(CKM.CKM_AES_GCM, [CryptoOperation.Unwrap], "AEAD.", MechanismChecks.GcmTagLength(128)));
    }

    // A built-in mechanism a derived policy removed was reviewed and deliberately dropped: "not reviewed, add it"
    // would be false on both counts.
    [Fact]
    public void RemovedMechanism_IsDeniedAsRemoved_WithoutTheHint()
    {
        CryptoPolicyBuilder b = CryptoPolicy.Recommended.ToBuilder("App").RemoveMechanism(CKM.CKM_AES_GCM);
        Assert.Equal("CKM_AES_GCM is not allowed: This policy removed it from its allow-list.",
            b.Build().Evaluate(new MechanismUseRequest(new Mechanism(CKM.CKM_AES_GCM), CryptoOperation.Encrypt)).Reason);
        Assert.True(Allowed(b.AllowMechanism(CKM.CKM_AES_GCM, [CryptoOperation.Encrypt], "Back.").Build(),
            new Mechanism(CKM.CKM_AES_GCM), CryptoOperation.Encrypt));

        ComposedCryptoPolicy neverAllowed = CryptoPolicy.Recommended.ToBuilder("App").RemoveMechanism(CKM.CKM_CAMELLIA_CBC).Build();
        Assert.EndsWith(RecommendedDefinition.UnlistedMechanismHint(new PolicyIdentity("App", null)),
            neverAllowed.Evaluate(new MechanismUseRequest(new Mechanism(CKM.CKM_CAMELLIA_CBC), CryptoOperation.Encrypt)).Reason);
    }

    [Fact]
    public void Names_AreStoredTrimmed()
    {
        Assert.Equal("App", new CryptoPolicyBuilder(" App ").Build().Name);
        Assert.Equal("App2", CryptoPolicy.Recommended.ToBuilder("App2 ").Build().Name);
    }

    // HashUseRequest names are the BCL's (HashAlgorithmName.SHA256 is "SHA256"); a differently cased known name must
    // not be stored as a key no request will ever match.
    [Fact]
    public void KnownHashNames_AreCanonicalised()
    {
        CryptoPolicyBuilder b = new CryptoPolicyBuilder("App").AllowHash(new HashAlgorithmName("sha256"), [CryptoOperation.Sign], "SHA-2.");
        Assert.True(b.Build().Evaluate(new HashUseRequest(HashAlgorithmName.SHA256, CryptoOperation.Sign)).IsAllowed);
        Assert.False(b.RemoveHash(new HashAlgorithmName("Sha256")).Build()
            .Evaluate(new HashUseRequest(HashAlgorithmName.SHA256, CryptoOperation.Sign)).IsAllowed);
    }

    // === Coverage the review asked for ========================================

    [Fact]
    public void ACopy_CarriesEveryTableOfItsSource()
    {
        PolicyCatalogue source = CryptoPolicy.Recommended.Catalogue;
        PolicyCatalogue copy = CryptoPolicy.Recommended.ToBuilder("App").Build().Catalogue;
        Assert.Equal(source.AllowedMechanisms.OrderBy(kv => kv.Key), copy.AllowedMechanisms.OrderBy(kv => kv.Key));
        Assert.Equal(source.AllowedVendorMechanisms.OrderBy(kv => kv.Key), copy.AllowedVendorMechanisms.OrderBy(kv => kv.Key));
        Assert.Equal(source.AllowedHashes.OrderBy(kv => kv.Key), copy.AllowedHashes.OrderBy(kv => kv.Key));
        Assert.Equal(source.AllowedCurves.OrderBy(kv => kv.Key), copy.AllowedCurves.OrderBy(kv => kv.Key));
        Assert.Equal(source.AllowedKdfs.OrderBy(kv => kv.Key), copy.AllowedKdfs.OrderBy(kv => kv.Key));
        Assert.Equal(source.AllowedKeyAgreementKeyTypes.OrderBy(kv => kv.Key), copy.AllowedKeyAgreementKeyTypes.OrderBy(kv => kv.Key));
        Assert.Equal(source.AllowedKdfPrfs.Keys.Order(), copy.AllowedKdfPrfs.Keys.Order());
        Assert.All(source.AllowedKdfPrfs, kv => Assert.True(kv.Value.SetEquals(copy.AllowedKdfPrfs[kv.Key])));
        Assert.Equal(source.DocumentedRefusedMechanisms.OrderBy(kv => kv.Key), copy.DocumentedRefusedMechanisms.OrderBy(kv => kv.Key));
        Assert.Equal(source.DocumentedRefusedHashes.OrderBy(kv => kv.Key), copy.DocumentedRefusedHashes.OrderBy(kv => kv.Key));
        Assert.Equal(source.DocumentedRefusedCurves.OrderBy(kv => kv.Key), copy.DocumentedRefusedCurves.OrderBy(kv => kv.Key));
        Assert.Equal(source.DocumentedRefusedKdfs.OrderBy(kv => kv.Key), copy.DocumentedRefusedKdfs.OrderBy(kv => kv.Key));
        Assert.Equal(source.DocumentedRefusedKeyAgreementKeyTypes.OrderBy(kv => kv.Key), copy.DocumentedRefusedKeyAgreementKeyTypes.OrderBy(kv => kv.Key));
        Assert.Equal(source.DocumentedRefusedPrfs.OrderBy(kv => kv.Key), copy.DocumentedRefusedPrfs.OrderBy(kv => kv.Key));
        Assert.Same(source.RsaKeyGeneration, copy.RsaKeyGeneration);
        Assert.Same(source.KeyTemplate, copy.KeyTemplate);
        Assert.Same(source.SecretExport, copy.SecretExport);
        Assert.Equal(source.UnlistedMechanismHint, copy.UnlistedMechanismHint);
    }

    [Fact]
    public void AWorkspaceUnderAFipsDerivedPolicy_RefusesOverrides()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.NistApproved.ToBuilder("FipsPlus").Build());
        Assert.Throws<InvalidOperationException>(() => workspace.UsePolicy(CryptoPolicy.AllowInsecure));
    }

    [Fact]
    public void Routing_IsByValue_StandardAndVendorTables()
    {
        ComposedCryptoPolicy p = new CryptoPolicyBuilder("App")
            .AllowMechanism(CKM.CKM_AES_GCM, [CryptoOperation.Encrypt], "AEAD.")
            .AllowMechanism((CKM)0x80001234UL, [CryptoOperation.Sign], "Vendor.")
            .Build();
        Assert.True(p.Catalogue.AllowedMechanisms.ContainsKey(CKM.CKM_AES_GCM));
        Assert.False(p.Catalogue.AllowedVendorMechanisms.ContainsKey((ulong)CKM.CKM_AES_GCM));
        Assert.True(p.Catalogue.AllowedVendorMechanisms.ContainsKey(0x80001234UL));
        Assert.False(p.Catalogue.AllowedMechanisms.ContainsKey((CKM)0x80001234UL));
    }

    // The session refuses CKM_HKDF_DATA whatever the policy (it writes the KDF output to a data object in the
    // clear), so a policy allowing it would document a permission that never takes effect.
    [Fact]
    public void HkdfData_CannotBeAllowed()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new CryptoPolicyBuilder("App").AllowMechanism(CKM.CKM_HKDF_DATA, [CryptoOperation.Derive], "x"));
        Assert.Equal("mechanism", ex.ParamName);
        Assert.Contains("CKM_HKDF_DERIVE", ex.Message);
        Assert.Throws<ArgumentException>(() =>
            new CryptoPolicyBuilder("App").AllowMechanismForLegacyUse(CKM.CKM_HKDF_DATA, [CryptoOperation.Derive], "x"));
    }

    [Fact]
    public void UndefinedKeyAgreementKdf_IsRejected() =>
        Assert.Equal("kdf", Assert.Throws<ArgumentException>(() =>
            new CryptoPolicyBuilder("App").AllowKeyAgreementKdf((CKD)0xFFFF, "x")).ParamName);

    // === Secret export opt-in ============================================

    [Fact]
    public void AllowSecretExport_AllowsOnlyThatKind()
    {
        ComposedCryptoPolicy p = CryptoPolicy.Recommended.ToBuilder("App")
            .AllowSecretExport(SecretExportKind.KdfOutput, "TLS exporter needs the bytes.")
            .Build();
        Assert.True(p.Evaluate(new SecretExportRequest(SecretExportKind.KdfOutput)).IsAllowed);
        PolicyDecision other = p.Evaluate(new SecretExportRequest(SecretExportKind.EcdhSharedSecret));
        Assert.False(other.IsAllowed);
        Assert.Contains("AllowSecretExport(SecretExportKind.EcdhSharedSecret, reason)", other.Reason, StringComparison.Ordinal);
        Assert.False(CryptoPolicy.Recommended.Evaluate(new SecretExportRequest(SecretExportKind.KdfOutput)).IsAllowed);
    }

    [Fact]
    public void AllowSecretExport_IsCopied_AndCanBeRemoved()
    {
        ComposedCryptoPolicy p = new CryptoPolicyBuilder("App")
            .AllowSecretExport(SecretExportKind.KemSharedSecret, "Hybrid KEM combiner runs in managed code.")
            .Build();
        ComposedCryptoPolicy copy = p.ToBuilder("App2").Build();
        Assert.True(copy.Evaluate(new SecretExportRequest(SecretExportKind.KemSharedSecret)).IsAllowed);
        ComposedCryptoPolicy removed = p.ToBuilder("App3").RemoveSecretExport(SecretExportKind.KemSharedSecret).Build();
        Assert.False(removed.Evaluate(new SecretExportRequest(SecretExportKind.KemSharedSecret)).IsAllowed);
    }

    [Fact]
    public void AllowSecretExport_ValidatesItsArguments()
    {
        Assert.Throws<ArgumentException>(() => new CryptoPolicyBuilder("App").AllowSecretExport((SecretExportKind)99, "x"));
        Assert.Throws<ArgumentException>(() => new CryptoPolicyBuilder("App").AllowSecretExport(SecretExportKind.KdfOutput, " "));
    }
}
