using System.Reflection;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

// ML-KEM encapsulation-key import is an evaluation-only BCL API.
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

/// <summary>
/// An explicit, per-kind <see cref="KeyMaterialExportRule.Allow"/> opt-in over <c>Recommended</c> must make
/// the library's own read-back paths work, and nothing else: the extractable, non-sensitive template (and,
/// for ECDH, the <c>CKD_NULL</c> derivation) such a path creates is judged by the export rule for its kind,
/// while the same template or derivation coming from a caller is still judged by the template and KDF rules.
/// Runs against the in-process <see cref="ManagedSoftToken"/>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class KeyMaterialExportOptInTests
{
    private static readonly HashAlgorithmName Sha256 = HashAlgorithmName.SHA256;
    private static readonly byte[] Ikm = Convert.FromHexString("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
    private static readonly byte[] Salt = Convert.FromHexString("000102030405060708090A0B0C");
    private static readonly byte[] Info = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9");

    private static readonly KeyMaterialExportKind[] AllKinds =
        [KeyMaterialExportKind.KdfOutput, KeyMaterialExportKind.EcdhSharedSecret, KeyMaterialExportKind.KemSharedSecret];

    private static ICryptoPolicy OptIn(params KeyMaterialExportKind[] kinds) =>
        CryptoPolicy.Recommended.ToBuilder("Opt-in")
            .WithKeyMaterialExportRule(KeyMaterialExportRule.Allow(kinds, "test"))
            .Build();

    private static void WithSession(ICryptoPolicy policy, Action<Pkcs11Session> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library, policy);
        body(session);
    }

    private static Pkcs11Key ImportIkm(Pkcs11Session session)
    {
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).Value(Ikm).Derive().Build();
        return session.ImportKey(tpl);
    }

    private static Pkcs11Key GenerateMlKem(Pkcs11Session session)
    {
        using var pub = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlKem.CKP_ML_KEM_768).Build();
        using var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Attribute(CKA.CKA_DECAPSULATE, true).Build();
        return session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), pub, priv);
    }

    private static Mechanism HkdfMechanism() =>
        new(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, Salt, Info));

    // A fresh P-256 peer's point, encoded as DeriveRawSecret hands it to CK_ECDH1_DERIVE_PARAMS.
    private static byte[] PeerPoint()
    {
        using var peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters p = peer.ExportParameters(includePrivateParameters: false);
        return EcPointEncoding.Encode(p.Q.X!, p.Q.Y!);
    }

    // === An allowed kind covers its own read-back ==============================================

    [Fact]
    public void KdfOutputAllowed_HkdfBytes_Succeeds() => WithSession(OptIn(KeyMaterialExportKind.KdfOutput), session =>
    {
        using var ikm = ImportIkm(session);

        byte[] okm = HkdfPkcs11.DeriveKey(Sha256, ikm, 32, Salt, Info);

        Assert.Equal(HKDF.DeriveKey(Sha256, Ikm, 32, Salt, Info), okm);
    });

    [Fact]
    public void EcdhAllowed_DeriveRawSecret_Succeeds() => WithSession(OptIn(KeyMaterialExportKind.EcdhSharedSecret), session =>
    {
        using var alice = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var alicePublic = ECDiffieHellman.Create();
        alicePublic.ImportSubjectPublicKeyInfo(alice.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo), out _);

        byte[] z = alice.DeriveRawSecret(bob.ExportSubjectPublicKeyInfo());

        Assert.Equal(bob.DeriveRawSecretAgreement(alicePublic.PublicKey), z);
    });

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void KemAllowed_MLKemDecapsulate_Succeeds() => WithSession(OptIn(KeyMaterialExportKind.KemSharedSecret), session =>
    {
        using var key = GenerateMlKem(session);
        using var mlkem = new MLKemPkcs11(key);
        using var sender = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, mlkem.ExportEncapsulationKey());
        sender.Encapsulate(out byte[] ciphertext, out byte[] expected);

        Assert.Equal(expected, mlkem.Decapsulate(ciphertext));
    });

    // === Another kind does not ===================================================================

    [Fact]
    public void OnlyKdfOutputAllowed_DeriveRawSecret_Throws() => WithSession(OptIn(KeyMaterialExportKind.KdfOutput), session =>
    {
        using var alice = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        var e = Assert.Throws<CryptoPolicyViolationException>(() => alice.DeriveRawSecret(bob.ExportSubjectPublicKeyInfo()));

        Assert.Equal(KeyMaterialExportKind.EcdhSharedSecret, Assert.IsType<KeyMaterialExportRequest>(e.Request).Kind);
    });

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void OnlyKdfOutputAllowed_MLKemDecapsulate_Throws() => WithSession(OptIn(KeyMaterialExportKind.KdfOutput), session =>
    {
        using var key = GenerateMlKem(session);
        using var mlkem = new MLKemPkcs11(key);
        using var sender = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, mlkem.ExportEncapsulationKey());
        sender.Encapsulate(out byte[] ciphertext, out _);

        var e = Assert.Throws<CryptoPolicyViolationException>(() => mlkem.Decapsulate(ciphertext));

        Assert.Equal(KeyMaterialExportKind.KemSharedSecret, Assert.IsType<KeyMaterialExportRequest>(e.Request).Kind);
    });

    // === A caller cannot ride on the opt-in ======================================================

    [Fact]
    public void ExportAllowed_CallerNonSensitiveTemplate_StillRefused() => WithSession(OptIn(AllKinds), session =>
    {
        using var ikm = ImportIkm(session);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Sensitive(false).Build();

        var e = Assert.Throws<CryptoPolicyViolationException>(() => ikm.Derive(HkdfMechanism(), template));

        Assert.Null(Assert.IsType<KeyTemplateRequest>(e.Request).ReadBackFor);
    });

    // The exact template DeriveRawSecret uses, and a sensitive working key: a caller's CKD_NULL derive is
    // refused by the KDF rule either way.
    public static TheoryData<bool> ReadBackShapedTemplate => [true, false];

    [Theory]
    [MemberData(nameof(ReadBackShapedTemplate))]
    public void ExportAllowed_CallerCkdNullDerive_StillRefused(bool readBackShaped) => WithSession(OptIn(AllKinds), session =>
    {
        using var alice = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, PeerPoint()));
        using var template = readBackShaped
            ? ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Extractable().Sensitive(false).Build()
            : ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Sign().Build();

        var e = Assert.Throws<CryptoPolicyViolationException>(() => alice.Derive(mechanism, template));

        var request = Assert.IsType<KeyAgreementKdfRequest>(e.Request);
        Assert.Equal(CKD.CKD_NULL, request.Kdf);
        Assert.Null(request.ReadBackFor);
    });

    [Fact]
    public void Recommended_HkdfBytes_StillRefused() => WithSession(CryptoPolicy.Recommended, session =>
    {
        using var ikm = ImportIkm(session);

        Assert.Throws<CryptoPolicyViolationException>(() => HkdfPkcs11.DeriveKey(Sha256, ikm, 32, Salt, Info));
    });

    // === What a custom policy sees ===============================================================

    // Allows everything and records every request.
    private sealed class RecordingPolicy : ICryptoPolicy
    {
        public List<PolicyRequest> Seen { get; } = [];
        public string Name => "Recording";
        public bool AllowsOverride => false;
        public PolicyDecision Evaluate(PolicyRequest request)
        {
            Seen.Add(request);
            return PolicyDecision.Allow;
        }
    }

    [Fact]
    public void CustomPolicy_SeesReadBackFor()
    {
        var policy = new RecordingPolicy();
        WithSession(policy, session =>
        {
            using var ikm = ImportIkm(session);
            policy.Seen.Clear();

            HkdfPkcs11.DeriveKey(Sha256, ikm, 32, Salt, Info);

            KeyTemplateRequest readBack = Assert.Single(policy.Seen.OfType<KeyTemplateRequest>(), r => r.ReadBackFor is not null);
            Assert.Equal(KeyMaterialExportKind.KdfOutput, readBack.ReadBackFor);

            policy.Seen.Clear();
            using var aes = session.GenerateAesKey();

            Assert.NotEmpty(policy.Seen.OfType<KeyTemplateRequest>());
            Assert.All(policy.Seen.OfType<KeyTemplateRequest>(), r => Assert.Null(r.ReadBackFor));
        });
    }

    [Fact]
    public void CustomPolicy_SeesReadBackForOnTheEcdhKdf()
    {
        var policy = new RecordingPolicy();
        WithSession(policy, session =>
        {
            using var alice = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
            using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            policy.Seen.Clear();

            alice.DeriveRawSecret(bob.ExportSubjectPublicKeyInfo());

            Assert.Equal(KeyMaterialExportKind.EcdhSharedSecret, Assert.Single(policy.Seen.OfType<KeyAgreementKdfRequest>()).ReadBackFor);
            Assert.Equal(KeyMaterialExportKind.EcdhSharedSecret, Assert.Single(policy.Seen.OfType<KeyTemplateRequest>()).ReadBackFor);

            policy.Seen.Clear();
            using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Extractable().Sensitive(false).Build();
            using var derived = alice.Derive(new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, PeerPoint())), template);

            Assert.Null(Assert.Single(policy.Seen.OfType<KeyAgreementKdfRequest>()).ReadBackFor);
            Assert.Null(Assert.Single(policy.Seen.OfType<KeyTemplateRequest>()).ReadBackFor);
        });
    }

    // === ML-KEM, where the platform cannot run it ================================================

    // MLKemPkcs11 over a fake ML-KEM-768 key whose module answers attribute reads only, so every policy
    // check runs and the token call then fails. Runs whether or not the platform supports ML-KEM.
    private static void WithFakeMlKem(ICryptoPolicy policy, bool publicOnly, Action<MLKemPkcs11> body)
    {
        using var key = FakeKeys.Create(CKK.CKK_ML_KEM, ca => ca switch
        {
            CKA.CKA_PARAMETER_SET => (CKR.CKR_OK, BitConverter.GetBytes((ulong)CkpMlKem.CKP_ML_KEM_768)),
            _ => (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null),
        }, policy, publicOnly: publicOnly);
        using var mlkem = new MLKemPkcs11(key);
        body(mlkem);
    }

    private static readonly Dictionary<string, (bool PublicOnly, Action<MLKemPkcs11> Run)> KemReadBacks = new()
    {
        ["Encapsulate"] = (true, k => k.Encapsulate(out _, out _)),
        ["Decapsulate"] = (false, k => k.Decapsulate(new byte[MLKemAlgorithm.MLKem768.CiphertextSizeInBytes])),
    };

    private static void AssertModuleRefused(Action call)
        => Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, Assert.ThrowsAny<Pkcs11Exception>(call).ReturnValue);

    public static TheoryData<string> KemReadBackNames() => [.. KemReadBacks.Keys];

    [Theory]
    [MemberData(nameof(KemReadBackNames))]
    public void KemReadBack_TemplateIsTaggedKemSharedSecret(string call)
    {
        var policy = new RecordingPolicy();
        (bool publicOnly, Action<MLKemPkcs11> run) = KemReadBacks[call];

        WithFakeMlKem(policy, publicOnly, mlkem => AssertModuleRefused(() => run(mlkem)));

        KeyTemplateRequest template = Assert.Single(policy.Seen.OfType<KeyTemplateRequest>());
        Assert.Equal(KeyMaterialExportKind.KemSharedSecret, template.ReadBackFor);
    }

    [Theory]
    [MemberData(nameof(KemReadBackNames))]
    public void KemAllowed_KemReadBack_PassesThePolicy(string call)
    {
        (bool publicOnly, Action<MLKemPkcs11> run) = KemReadBacks[call];

        // Past every policy check: the fake module, not the policy, refuses.
        WithFakeMlKem(OptIn(KeyMaterialExportKind.KemSharedSecret), publicOnly, mlkem => AssertModuleRefused(() => run(mlkem)));
    }

    // === The tag is the library's alone ==========================================================

    [Theory]
    [InlineData(typeof(KeyTemplateRequest))]
    [InlineData(typeof(KeyAgreementKdfRequest))]
    public void ReadBackFor_CannotBeSetFromOutsideTheLibrary(Type requestType)
    {
        PropertyInfo property = requestType.GetProperty("ReadBackFor")!;

        Assert.True(property.GetMethod!.IsPublic);
        Assert.True(property.SetMethod!.IsAssembly);
    }

    [Fact]
    public void Describe_NamesTheReadBack()
    {
        var request = new KeyTemplateRequest(CKO.CKO_SECRET_KEY, []) { ReadBackFor = KeyMaterialExportKind.KdfOutput };

        Assert.Equal("key template (CKO_SECRET_KEY) (read-back for KdfOutput)", request.Describe());
        Assert.Equal("key template (CKO_SECRET_KEY)", new KeyTemplateRequest(CKO.CKO_SECRET_KEY, []).Describe());
    }
}
