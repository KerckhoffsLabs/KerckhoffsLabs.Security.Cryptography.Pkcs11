using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

#pragma warning disable KLPKCS11007, KLPKCS11009 // weak curves and mechanisms are the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>
/// Tests for the Recommended opt-ins that are not about a mechanism —
/// <see cref="CryptoPolicyBuilder.AllowSecretExport"/>, <see cref="CryptoPolicyBuilder.AllowCurve(Pkcs11ECCurve, string)"/>
/// and <see cref="CryptoPolicyBuilder.AllowKeyAgreementKdf"/> on a copy of Recommended: each allows exactly what it
/// names and leaves every other Recommended rule in force.
/// </summary>
[NoBackendCollection("Evaluates policies directly and drives a per-test ManagedSoftToken in process — no " +
                     "native module is loaded, so this is safe alongside every backend collection.")]
public sealed class RecommendedPolicyNarrowOptInTests
{
    private const string Reason = "Reviewed for this deployment.";

    private static bool Allowed(ComposedCryptoPolicy policy, PolicyRequest request) => policy.Evaluate(request).IsAllowed;

    private static SecretExportRequest Export(SecretExportKind kind) => new(kind);

    private static CryptoPolicyBuilder RecommendedCopy() => CryptoPolicy.Recommended.ToBuilder("Test");

    // === Secret export =================================================

    [Fact]
    public void SecretExport_AllowsOnlyTheNamedKind()
    {
        ComposedCryptoPolicy policy = RecommendedCopy().AllowSecretExport(SecretExportKind.EcdhSharedSecret, Reason).Build();

        Assert.True(Allowed(policy, Export(SecretExportKind.EcdhSharedSecret)));
        Assert.False(Allowed(policy, Export(SecretExportKind.KemSharedSecret)));
        Assert.False(Allowed(policy, Export(SecretExportKind.KdfOutput)));
    }

    [Fact]
    public void SecretExport_LayersWithEarlierOptIns()
    {
        ComposedCryptoPolicy policy = RecommendedCopy()
            .AllowSecretExport(SecretExportKind.EcdhSharedSecret, Reason)
            .AllowSecretExport(SecretExportKind.KdfOutput, Reason)
            .AllowMechanism(CKM.CKM_DES_CBC, [CryptoOperation.Decrypt], Reason)
            .Build();

        Assert.True(Allowed(policy, Export(SecretExportKind.EcdhSharedSecret)));
        Assert.True(Allowed(policy, Export(SecretExportKind.KdfOutput)));
        Assert.False(Allowed(policy, Export(SecretExportKind.KemSharedSecret)));
        Assert.True(Allowed(policy, new MechanismUseRequest(new Mechanism(CKM.CKM_DES_CBC), CryptoOperation.Decrypt)));
    }

    [Fact]
    public void SecretExport_KeepsTheKeyTemplateRule()
    {
        ComposedCryptoPolicy policy = RecommendedCopy().AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build();
        using var nonSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);

        Assert.False(Allowed(policy, new KeyTemplateRequest(CKO.CKO_SECRET_KEY, [nonSensitive])));
    }

    [Fact]
    public void OptIns_LeaveRecommendedUnchanged()
    {
        ComposedCryptoPolicy receiver = CryptoPolicy.Recommended;

        _ = receiver.ToBuilder("Test")
            .AllowSecretExport(SecretExportKind.EcdhSharedSecret, Reason)
            .AllowCurve(Pkcs11ECCurve.NamedCurves.NistP192, Reason)
            .AllowKeyAgreementKdf(CKD.CKD_NULL, Reason)
            .Build();

        Assert.False(Allowed(receiver, Export(SecretExportKind.EcdhSharedSecret)));
        Assert.False(Allowed(receiver, new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP192)));
        Assert.False(Allowed(receiver, new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL)));
        Assert.Equal("Recommended", CryptoPolicy.Recommended.Name);
    }

    [Theory]
    [InlineData(SecretExportKind.EcdhSharedSecret, "Pkcs11Workspace.DeriveSharedSecretEcdh")]
    [InlineData(SecretExportKind.KemSharedSecret, "Pkcs11Key.EncapsulateKey")]
    [InlineData(SecretExportKind.KdfOutput, "HkdfPkcs11")]
    [InlineData(SecretExportKind.PasswordKdfOutput, "Rfc2898DeriveBytesPkcs11.Pbkdf2Key")]
    public void SecretExport_Refusal_NamesTheOnTokenAlternativeAndTheOptIn(SecretExportKind kind, string alternative)
    {
        PolicyDecision decision = CryptoPolicy.Recommended.Evaluate(Export(kind));

        Assert.False(decision.IsAllowed);
        Assert.Contains(alternative, decision.Reason);
        Assert.Contains($"AllowSecretExport(SecretExportKind.{kind}, reason)", decision.Reason);
    }

    [Fact]
    public void SecretExport_ReasonAppearsInTheRenderedCatalogue()
    {
        ComposedCryptoPolicy policy = RecommendedCopy().AllowSecretExport(SecretExportKind.KdfOutput, "export-reason-marker").Build();

        Assert.Contains("export-reason-marker", PolicyCatalogueMarkdown.Render(policy.Catalogue, policy.Name));
    }

    // === Curves ==============================================================

    [Fact]
    public void Curve_AllowsOnlyTheNamedCurve()
    {
        ComposedCryptoPolicy policy = RecommendedCopy().AllowCurve(Pkcs11ECCurve.NamedCurves.NistP192, "curve-reason-marker").Build();

        Assert.True(Allowed(policy, new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP192)));
        Assert.False(Allowed(policy, new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.Secp192k1)));
        Assert.True(Allowed(policy, new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP256)));
        Assert.Contains("curve-reason-marker", PolicyCatalogueMarkdown.Render(policy.Catalogue, policy.Name));
    }

    [Fact]
    public void Curve_RejectsAnUnnamedCurve()
    {
        var e = Assert.Throws<ArgumentException>(() => RecommendedCopy().AllowCurve(default(Pkcs11ECCurve), Reason));
        Assert.Equal("curve", e.ParamName);
    }

    // === Key-agreement KDFs ==================================================

    [Fact]
    public void KeyAgreementKdf_AllowsOnlyTheNamedKdf()
    {
        Assert.False(Allowed(CryptoPolicy.Recommended, new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL)));

        ComposedCryptoPolicy policy = RecommendedCopy().AllowKeyAgreementKdf(CKD.CKD_NULL, "kdf-reason-marker").Build();

        Assert.True(Allowed(policy, new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL)));
        Assert.False(Allowed(policy, new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_SHA1_KDF)));
        Assert.Contains("kdf-reason-marker", PolicyCatalogueMarkdown.Render(policy.Catalogue, policy.Name));
    }

    // === End to end: the opt-in is enough for the adapter ====================

    [Fact]
    public void EcdhRawSecret_IsRefusedUnderRecommended()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var ecdh = new ECDiffieHellmanPkcs11(key);
        using var peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        Assert.Throws<CryptoPolicyViolationException>(() => ecdh.DeriveRawSecretAgreement(peer.PublicKey));
    }

    [Fact]
    public void EcdhRawSecret_WorksWithOnlyTheExportOptIn_AndMatchesTheBcl()
    {
        using var library = ManagedToken.NewLibrary();
        ComposedCryptoPolicy policy = RecommendedCopy().AllowSecretExport(SecretExportKind.EcdhSharedSecret, Reason).Build();
        using var workspace = ManagedToken.OpenWorkspace(library, policy);
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var ecdh = new ECDiffieHellmanPkcs11(key);
        using var peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        byte[] ours = ecdh.DeriveRawSecretAgreement(peer.PublicKey);
        byte[] theirs = peer.DeriveRawSecretAgreement(ecdh.PublicKey);

        Assert.Equal(theirs, ours);
    }

    [Fact]
    public void Sp800108Output_WorksWithOnlyTheExportOptIn_AndMatchesTheBcl()
    {
        byte[] keyBytes = [.. Enumerable.Range(0, 32).Select(i => (byte)(i + 1))];
        using var library = ManagedToken.NewLibrary();
        ComposedCryptoPolicy policy = RecommendedCopy().AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build();
        using var workspace = ManagedToken.OpenWorkspace(library, policy);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).Value(keyBytes).Derive().Build();
        using var key = workspace.ImportKey(template);
        using var kdf = new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.SHA256);

        byte[] ours = kdf.DeriveKey("label"u8.ToArray(), "context"u8.ToArray(), 32);
        byte[] expected = SP800108HmacCounterKdf.DeriveBytes(keyBytes, HashAlgorithmName.SHA256, "label"u8.ToArray(), "context"u8.ToArray(), 32);

        Assert.Equal(expected, ours);
    }

    [Fact]
    public void ReadBackWaiver_EndsWithTheAdapterCall()
    {
        using var library = ManagedToken.NewLibrary();
        ComposedCryptoPolicy policy = RecommendedCopy().AllowSecretExport(SecretExportKind.EcdhSharedSecret, Reason).Build();
        using var workspace = ManagedToken.OpenWorkspace(library, policy);
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var ecdh = new ECDiffieHellmanPkcs11(key);
        using var peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        _ = ecdh.DeriveRawSecretAgreement(peer.PublicKey);

        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Value(new byte[32]).Sensitive(false).Build();

        Assert.Throws<CryptoPolicyViolationException>(() => workspace.ImportKey(template));
    }
}
