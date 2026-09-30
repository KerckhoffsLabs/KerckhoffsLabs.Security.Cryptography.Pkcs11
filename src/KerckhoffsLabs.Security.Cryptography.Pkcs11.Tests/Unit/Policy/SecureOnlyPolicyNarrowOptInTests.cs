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
/// Tests for the SecureOnly opt-ins that are not about a mechanism —
/// <see cref="SecureOnlyPolicy.WithAllowedKeyMaterialExport"/>, <see cref="SecureOnlyPolicy.WithAllowedCurve"/>
/// and <see cref="SecureOnlyPolicy.WithAllowedKeyAgreementKdf"/>: each allows exactly what it names and
/// leaves every other SecureOnly rule in force.
/// </summary>
[NoBackendCollection("Evaluates policies directly and drives a per-test ManagedSoftToken in process — no " +
                     "native module is loaded, so this is safe alongside every backend collection.")]
public sealed class SecureOnlyPolicyNarrowOptInTests
{
    private const string Reason = "Reviewed for this deployment.";

    private static bool Allowed(SecureOnlyPolicy policy, PolicyRequest request) => policy.Evaluate(request).IsAllowed;

    private static KeyMaterialExportRequest Export(KeyMaterialExportKind kind) => new(kind);

    // === Key-material export =================================================

    [Fact]
    public void KeyMaterialExport_AllowsOnlyTheNamedKind()
    {
        SecureOnlyPolicy policy = CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.EcdhSharedSecret, Reason);

        Assert.True(Allowed(policy, Export(KeyMaterialExportKind.EcdhSharedSecret)));
        Assert.False(Allowed(policy, Export(KeyMaterialExportKind.KemSharedSecret)));
        Assert.False(Allowed(policy, Export(KeyMaterialExportKind.KdfOutput)));
        Assert.Equal("SecureOnly+custom", policy.Name);
    }

    [Fact]
    public void KeyMaterialExport_LayersWithEarlierOptIns()
    {
        SecureOnlyPolicy policy = CryptoPolicy.SecureOnly
            .WithAllowedKeyMaterialExport(KeyMaterialExportKind.EcdhSharedSecret, Reason)
            .WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, Reason)
            .WithAllowedMechanism(CKM.CKM_DES_CBC, [CryptoOperation.Decrypt], Reason);

        Assert.True(Allowed(policy, Export(KeyMaterialExportKind.EcdhSharedSecret)));
        Assert.True(Allowed(policy, Export(KeyMaterialExportKind.KdfOutput)));
        Assert.False(Allowed(policy, Export(KeyMaterialExportKind.KemSharedSecret)));
        Assert.True(Allowed(policy, new MechanismUseRequest(new Mechanism(CKM.CKM_DES_CBC), CryptoOperation.Decrypt)));
    }

    [Fact]
    public void KeyMaterialExport_KeepsTheKeyTemplateRule()
    {
        SecureOnlyPolicy policy = CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, Reason);
        using var nonSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);

        Assert.False(Allowed(policy, new KeyTemplateRequest(CKO.CKO_SECRET_KEY, [nonSensitive])));
    }

    [Fact]
    public void OptIns_LeaveTheReceiverAndBaseSecureOnlyUnchanged()
    {
        SecureOnlyPolicy receiver = CryptoPolicy.SecureOnly;

        _ = receiver.WithAllowedKeyMaterialExport(KeyMaterialExportKind.EcdhSharedSecret, Reason);
        _ = receiver.WithAllowedCurve(Pkcs11ECCurve.NamedCurves.NistP192, Reason);
        _ = receiver.WithAllowedKeyAgreementKdf(CKD.CKD_NULL, Reason);

        Assert.False(Allowed(receiver, Export(KeyMaterialExportKind.EcdhSharedSecret)));
        Assert.False(Allowed(receiver, new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP192)));
        Assert.False(Allowed(receiver, new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL)));
        Assert.Equal("SecureOnly", CryptoPolicy.SecureOnly.Name);
    }

    [Theory]
    [InlineData(KeyMaterialExportKind.EcdhSharedSecret, "Pkcs11Workspace.DeriveSharedSecretEcdh")]
    [InlineData(KeyMaterialExportKind.KemSharedSecret, "Pkcs11Key.EncapsulateKey")]
    [InlineData(KeyMaterialExportKind.KdfOutput, "HkdfPkcs11")]
    [InlineData(KeyMaterialExportKind.PasswordKdfOutput, "Rfc2898DeriveBytesPkcs11.Pbkdf2Key")]
    public void KeyMaterialExport_Refusal_NamesTheOnTokenAlternativeAndTheOptIn(KeyMaterialExportKind kind, string alternative)
    {
        PolicyDecision decision = CryptoPolicy.SecureOnly.Evaluate(Export(kind));

        Assert.False(decision.IsAllowed);
        Assert.Contains(alternative, decision.Reason);
        Assert.Contains($"WithAllowedKeyMaterialExport(KeyMaterialExportKind.{kind}, reason)", decision.Reason);
    }

    [Fact]
    public void KeyMaterialExport_ReasonAppearsInTheRenderedCatalogue()
    {
        SecureOnlyPolicy policy = CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, "export-reason-marker");

        Assert.Contains("export-reason-marker", PolicyCatalogueMarkdown.Render(policy.Catalogue, policy.Name));
    }

    // === Curves ==============================================================

    [Fact]
    public void Curve_AllowsOnlyTheNamedCurve()
    {
        SecureOnlyPolicy policy = CryptoPolicy.SecureOnly.WithAllowedCurve(Pkcs11ECCurve.NamedCurves.NistP192, "curve-reason-marker");

        Assert.True(Allowed(policy, new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP192)));
        Assert.False(Allowed(policy, new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.Secp192k1)));
        Assert.True(Allowed(policy, new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP256)));
        Assert.Contains("curve-reason-marker", PolicyCatalogueMarkdown.Render(policy.Catalogue, policy.Name));
    }

    [Fact]
    public void Curve_AlreadyAllowed_KeepsItsRationaleAndAppendsTheReason()
    {
        string oid = Pkcs11ECCurve.NamedCurves.NistP256.Oid!;
        string before = CryptoPolicy.SecureOnly.Catalogue.AllowedCurves[oid];

        SecureOnlyPolicy policy = CryptoPolicy.SecureOnly.WithAllowedCurve(Pkcs11ECCurve.NamedCurves.NistP256, Reason);

        Assert.Equal($"{before} Extended: {Reason}", policy.Catalogue.AllowedCurves[oid]);
    }

    [Fact]
    public void Curve_RejectsAnUnnamedCurve()
    {
        var e = Assert.Throws<ArgumentException>(() => CryptoPolicy.SecureOnly.WithAllowedCurve(default, Reason));
        Assert.Equal("curve", e.ParamName);
    }

    // === Key-agreement KDFs ==================================================

    [Fact]
    public void KeyAgreementKdf_AllowsOnlyTheNamedKdf()
    {
        Assert.False(Allowed(CryptoPolicy.SecureOnly, new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL)));

        SecureOnlyPolicy policy = CryptoPolicy.SecureOnly.WithAllowedKeyAgreementKdf(CKD.CKD_NULL, "kdf-reason-marker");

        Assert.True(Allowed(policy, new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL)));
        Assert.False(Allowed(policy, new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_SHA1_KDF)));
        Assert.Contains("kdf-reason-marker", PolicyCatalogueMarkdown.Render(policy.Catalogue, policy.Name));
    }

    // === Argument validation =================================================

    [Fact]
    public void UndefinedEnumValues_AreRejected()
    {
        Assert.Equal("kind", Assert.Throws<ArgumentException>(() =>
            CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport((KeyMaterialExportKind)99, Reason)).ParamName);
        Assert.Equal("kdf", Assert.Throws<ArgumentException>(() =>
            CryptoPolicy.SecureOnly.WithAllowedKeyAgreementKdf((CKD)0xFFFF, Reason)).ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void BlankReason_IsRejected(string? reason)
    {
        Assert.ThrowsAny<ArgumentException>(() => CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, reason!));
        Assert.ThrowsAny<ArgumentException>(() => CryptoPolicy.SecureOnly.WithAllowedCurve(Pkcs11ECCurve.NamedCurves.NistP192, reason!));
        Assert.ThrowsAny<ArgumentException>(() => CryptoPolicy.SecureOnly.WithAllowedKeyAgreementKdf(CKD.CKD_NULL, reason!));
    }

    // === End to end: the opt-in is enough for the adapter ====================

    [Fact]
    public void EcdhRawSecret_IsRefusedUnderSecureOnly()
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
        SecureOnlyPolicy policy = CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.EcdhSharedSecret, Reason);
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
        SecureOnlyPolicy policy = CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, Reason);
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
        SecureOnlyPolicy policy = CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.EcdhSharedSecret, Reason);
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
