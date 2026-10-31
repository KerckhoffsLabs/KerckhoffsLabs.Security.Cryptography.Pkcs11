using System.Reflection;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

// ML-KEM encapsulation-key import is an evaluation-only BCL API.
#pragma warning disable SYSLIB5006

#pragma warning disable KLPKCS11012 // the export opt-in is the subject under test

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
            CKA.CKA_PARAMETER_SET => (CKR.CKR_OK, BitConverter.GetBytes((ulong)CkpMlKem.CKP_ML_KEM_768).AsSpan(0, UnmanagedMemory.NativeULongSize).ToArray()),
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

    // === Pkcs11Key.DeriveBytes =====================================================================

    private static readonly byte[] Label = "label"u8.ToArray();
    private static readonly byte[] Context = "context"u8.ToArray();

    [Fact]
    public void DeriveBytes_KdfOutputAllowed_Hkdf_MatchesBcl() => WithSession(OptIn(KeyMaterialExportKind.KdfOutput), session =>
    {
        using var ikm = ImportIkm(session);

        byte[] okm = ikm.DeriveBytes(HkdfMechanism(), 42);

        Assert.Equal(HKDF.DeriveKey(Sha256, Ikm, 42, Salt, Info), okm);
    });

    // A token that ignores CKA_VALUE_LEN hands back more or less than the caller asked for; the read-back
    // must refuse it rather than return a truncated or oversized key.
    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public void DeriveBytes_TokenReturnsWrongLength_ThrowsCryptographicException(int skew)
    {
        var token = new ManagedSoftToken();
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library, OptIn(KeyMaterialExportKind.KdfOutput));
        using var ikm = ImportIkm(session);
        token.ValueLengthSkew = skew;

        Assert.Throws<CryptographicException>(() => ikm.DeriveBytes(HkdfMechanism(), 42));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public void HkdfDeriveKey_TokenReturnsWrongLength_ThrowsCryptographicException(int skew)
    {
        var token = new ManagedSoftToken();
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library, OptIn(KeyMaterialExportKind.KdfOutput));
        using var ikm = ImportIkm(session);
        token.ValueLengthSkew = skew; // after the import, whose CKA_VALUE read is not under test

        Assert.Throws<CryptographicException>(() => HkdfPkcs11.DeriveKey(Sha256, ikm, 32, Salt, Info));
    }

    [Fact]
    public void DeriveBytes_Sp800108Counter_TokenReturnsWrongLength_Throws()
    {
        var token = new ManagedSoftToken();
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library, OptIn(KeyMaterialExportKind.KdfOutput));
        using var ikm = ImportIkm(session);
        token.ValueLengthSkew = 1;
        var mechanism = new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF,
            CkmSp800108KdfParams.CounterModeHmac(CKM.CKM_SHA256_HMAC, Label, Context));

        Assert.Throws<CryptographicException>(() => ikm.DeriveBytes(mechanism, 32));
    }

    [Fact]
    public void DeriveBytes_KdfOutputAllowed_Sp800108Counter_MatchesBcl() => WithSession(OptIn(KeyMaterialExportKind.KdfOutput), session =>
    {
        using var ikm = ImportIkm(session);
        var mechanism = new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF,
            CkmSp800108KdfParams.CounterModeHmac(CKM.CKM_SHA256_HMAC, Label, Context));

        byte[] okm = ikm.DeriveBytes(mechanism, 32);

        Assert.Equal(SP800108HmacCounterKdf.DeriveBytes(Ikm, Sha256, Label, Context, 32), okm);
    });

    // Review Focus 1: DeriveBytes is the KdfOutput read-back, so a key-agreement mechanism handed to it must
    // never come back as Z. It is refused as the caller's argument, before the policy sees anything.
    [Fact]
    public void DeriveBytes_EcdhMechanism_ThrowsArgumentException()
    {
        var policy = new RecordingPolicy();
        WithSession(policy, session =>
        {
            using var alice = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
            var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, PeerPoint()));
            policy.Seen.Clear();

            var e = Assert.Throws<ArgumentException>(() => alice.DeriveBytes(mechanism, 32));

            Assert.Equal("mechanism", e.ParamName);
            Assert.Empty(policy.Seen);
        });

        // And under the KdfOutput opt-in, the policy that would otherwise let a KdfOutput read-back through.
        WithSession(OptIn(KeyMaterialExportKind.KdfOutput), session =>
        {
            using var alice = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
            var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, PeerPoint()));

            Assert.Throws<ArgumentException>(() => alice.DeriveBytes(mechanism, 32));
        });
    }

    public static TheoryData<string> NotAKdfOutput => [.. NotAKdfOutputMechanisms.Keys];

    private static readonly Dictionary<string, Func<Mechanism>> NotAKdfOutputMechanisms = new()
    {
        ["ECDH cofactor"] = () => new Mechanism(CKM.CKM_ECDH1_COFACTOR_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, PeerPoint())),
        ["SHA-256 HMAC"] = () => new Mechanism(CKM.CKM_SHA256_HMAC),
        ["AES ECB encrypt data"] = () => new Mechanism(CKM.CKM_AES_ECB_ENCRYPT_DATA),
        ["HKDF with ECDH parameters"] = () => new Mechanism(CKM.CKM_HKDF_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, PeerPoint())),
        ["HKDF with no parameters"] = () => new Mechanism(CKM.CKM_HKDF_DERIVE),
        // CKM_HKDF_DATA makes a data object, which the secret-key read-back cannot read; CKM_HKDF_DERIVE covers it.
        ["HKDF data"] = () => new Mechanism(CKM.CKM_HKDF_DATA, CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, Salt, Info)),
        ["SP 800-108 counter with HKDF parameters"] = () => new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF,
            CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, Salt, Info)),
        ["SP 800-108 feedback with counter parameters"] = () => new Mechanism(CKM.CKM_SP800_108_FEEDBACK_KDF,
            CkmSp800108KdfParams.CounterModeHmac(CKM.CKM_SHA256_HMAC, Label, Context)),
        ["SP 800-108 with an additional derived key"] = () =>
        {
            // Not disposed: the mechanism keeps the sibling's attributes, and the call is refused before marshalling.
            ObjectTemplate sibling = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(16).Sensitive(false).Extractable().Build();
            return new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC)
                .IterationCounter().ByteArray(Label).AddDerivedKey(sibling.Attributes).Build());
        },
    };

    [Theory]
    [MemberData(nameof(NotAKdfOutput))]
    public void DeriveBytes_NotAKdfOutputMechanism_ThrowsArgumentException(string name)
    {
        var policy = new RecordingPolicy();
        WithSession(policy, session =>
        {
            using var ikm = ImportIkm(session);
            Mechanism mechanism = NotAKdfOutputMechanisms[name]();
            policy.Seen.Clear();

            Assert.Throws<ArgumentException>(() => ikm.DeriveBytes(mechanism, 32));

            Assert.Empty(policy.Seen);
        });
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void DeriveBytes_NonPositiveLength_Throws(int length) => WithSession(OptIn(KeyMaterialExportKind.KdfOutput), session =>
    {
        using var ikm = ImportIkm(session);

        var e = Assert.Throws<ArgumentOutOfRangeException>(() => ikm.DeriveBytes(HkdfMechanism(), length));

        Assert.Equal("length", e.ParamName);
    });

    [Fact]
    public void DeriveBytes_NullMechanism_Throws() => WithSession(OptIn(KeyMaterialExportKind.KdfOutput), session =>
    {
        using var ikm = ImportIkm(session);

        Assert.Throws<ArgumentNullException>(() => ikm.DeriveBytes(null!, 32));
    });

    [Fact]
    public void DeriveBytes_UnderRecommended_ThrowsPolicyViolation() => WithSession(CryptoPolicy.Recommended, session =>
    {
        using var ikm = ImportIkm(session);

        var e = Assert.Throws<CryptoPolicyViolationException>(() => ikm.DeriveBytes(HkdfMechanism(), 32));

        Assert.Equal(KeyMaterialExportKind.KdfOutput, Assert.IsType<KeyMaterialExportRequest>(e.Request).Kind);
    });

    [Fact]
    public void DeriveBytes_OnlyOtherKindsAllowed_ThrowsPolicyViolation() => WithSession(
        OptIn(KeyMaterialExportKind.EcdhSharedSecret, KeyMaterialExportKind.KemSharedSecret), session =>
    {
        using var ikm = ImportIkm(session);

        var e = Assert.Throws<CryptoPolicyViolationException>(() => ikm.DeriveBytes(HkdfMechanism(), 32));

        Assert.Equal(KeyMaterialExportKind.KdfOutput, Assert.IsType<KeyMaterialExportRequest>(e.Request).Kind);
    });

    [Fact]
    public void DeriveBytes_TagsItsTemplateKdfOutput()
    {
        var policy = new RecordingPolicy();
        WithSession(policy, session =>
        {
            using var ikm = ImportIkm(session);
            policy.Seen.Clear();

            ikm.DeriveBytes(HkdfMechanism(), 32);

            Assert.Equal(KeyMaterialExportKind.KdfOutput, Assert.Single(policy.Seen.OfType<KeyMaterialExportRequest>()).Kind);
            Assert.Equal(KeyMaterialExportKind.KdfOutput, Assert.Single(policy.Seen.OfType<KeyTemplateRequest>()).ReadBackFor);
        });
    }

    // === The KdfOutput tag never covers a CKD_NULL derivation ===================================

    // The controller ruling: a tagged KeyAgreementKdfRequest is judged by the export rule only for the
    // EcdhSharedSecret read-back. Any other tag is judged as if untagged, so a KdfOutput-only opt-in cannot
    // approve a CKD_NULL derivation, which would return Z.
    [Fact]
    public void KdfOutputTaggedCkdNullRequest_IsJudgedAsUntagged()
    {
        ICryptoPolicy policy = OptIn(KeyMaterialExportKind.KdfOutput);
        var untagged = new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL);

        foreach (KeyMaterialExportKind kind in new[] { KeyMaterialExportKind.KdfOutput, KeyMaterialExportKind.KemSharedSecret })
        {
            PolicyDecision tagged = policy.Evaluate(untagged with { ReadBackFor = kind });

            Assert.False(tagged.IsAllowed);
            Assert.Equal(policy.Evaluate(untagged).Reason, tagged.Reason);
        }

        // Even with every kind allowed, only the EcdhSharedSecret tag reaches the export rule.
        ICryptoPolicy all = OptIn(AllKinds);
        Assert.False(all.Evaluate(untagged with { ReadBackFor = KeyMaterialExportKind.KdfOutput }).IsAllowed);
        Assert.True(all.Evaluate(untagged with { ReadBackFor = KeyMaterialExportKind.EcdhSharedSecret }).IsAllowed);
    }

    // === DeriveRawSecret on a Montgomery (X25519 / X448) key =====================================

    // RFC 7748 §6.1 and §6.2: Bob's public key and the secret Alice shares with him.
    private static readonly byte[] X25519BobPublic =
        Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    private static readonly byte[] X25519Shared =
        Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    private static readonly byte[] X448BobPublic = Convert.FromHexString(
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
    private static readonly byte[] X448Shared = Convert.FromHexString(
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

    // CKA_EC_PARAMS: the RFC 8410 OID, or the PrintableString curve name PKCS#11 v3.0 §2.3.10 also allows.
    private static readonly byte[] X25519Oid = [0x06, 0x03, 0x2B, 0x65, 0x6E];
    private static readonly byte[] X448Oid = [0x06, 0x03, 0x2B, 0x65, 0x6F];
    private static readonly byte[] X25519Name = [0x13, 0x0A, .. "curve25519"u8];
    private static readonly byte[] X448Name = [0x13, 0x08, .. "curve448"u8];

    // RFC 8410 §4: SEQUENCE { SEQUENCE { OID [, parameters] }, BIT STRING key }.
    private static byte[] MontgomerySpki(string oid, byte[] key, bool withNullParameters = false)
    {
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(oid);
                if (withNullParameters)
                    writer.WriteNull();
            }
            writer.WriteBitString(key);
        }
        return writer.Encode();
    }

    private static void WithMontgomeryKey(byte[] ecParams, byte[] tokenSecret, ICryptoPolicy policy,
        Action<Pkcs11Key, MontgomeryAgreementModule> body)
    {
        var module = new MontgomeryAgreementModule(ecParams, tokenSecret);
        using var key = module.CreateKey(policy);
        body(key, module);
    }

    public static TheoryData<string> MontgomeryCurves => ["X25519", "X25519 (curve name)", "X448", "X448 (curve name)"];

    private static (byte[] EcParams, string Oid, byte[] Peer, byte[] Shared) Curve(string name) => name switch
    {
        "X25519" => (X25519Oid, "1.3.101.110", X25519BobPublic, X25519Shared),
        "X25519 (curve name)" => (X25519Name, "1.3.101.110", X25519BobPublic, X25519Shared),
        "X448" => (X448Oid, "1.3.101.111", X448BobPublic, X448Shared),
        "X448 (curve name)" => (X448Name, "1.3.101.111", X448BobPublic, X448Shared),
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    [Theory]
    [MemberData(nameof(MontgomeryCurves))]
    public void EcdhAllowed_MontgomeryDeriveRawSecret_SendsTheRawUCoordinate(string curve)
    {
        (byte[] ecParams, string oid, byte[] peer, byte[] shared) = Curve(curve);
        WithMontgomeryKey(ecParams, shared, OptIn(KeyMaterialExportKind.EcdhSharedSecret), (key, module) =>
        {
            byte[] z = key.DeriveRawSecret(MontgomerySpki(oid, peer));

            Assert.Equal(shared, z);
            Assert.Equal(CKM.CKM_ECDH1_DERIVE, module.DerivedWith);
            Assert.Equal(CKD.CKD_NULL, module.Kdf);
            Assert.Equal(peer, module.PublicData);
            Assert.Equal((ulong)shared.Length, module.ValueLen);
            Assert.Equal([3UL], module.Destroyed);
        });
    }

    [Fact]
    public void OnlyKdfOutputAllowed_MontgomeryDeriveRawSecret_Throws() =>
        WithMontgomeryKey(X25519Oid, X25519Shared, OptIn(KeyMaterialExportKind.KdfOutput), (key, module) =>
        {
            var e = Assert.Throws<CryptoPolicyViolationException>(() => key.DeriveRawSecret(MontgomerySpki("1.3.101.110", X25519BobPublic)));

            Assert.Equal(KeyMaterialExportKind.EcdhSharedSecret, Assert.IsType<KeyMaterialExportRequest>(e.Request).Kind);
            Assert.Null(module.DerivedWith);
        });

    [Fact]
    public void MontgomeryDeriveRawSecret_TagsTheKdfAndTemplate()
    {
        var policy = new RecordingPolicy();
        WithMontgomeryKey(X25519Oid, X25519Shared, policy, (key, _) =>
        {
            key.DeriveRawSecret(MontgomerySpki("1.3.101.110", X25519BobPublic));

            Assert.Equal(KeyMaterialExportKind.EcdhSharedSecret, Assert.Single(policy.Seen.OfType<KeyMaterialExportRequest>()).Kind);
            Assert.Equal(KeyMaterialExportKind.EcdhSharedSecret, Assert.Single(policy.Seen.OfType<KeyAgreementKdfRequest>()).ReadBackFor);
            Assert.Equal(KeyMaterialExportKind.EcdhSharedSecret, Assert.Single(policy.Seen.OfType<KeyTemplateRequest>()).ReadBackFor);
            Assert.Equal(CKK.CKK_EC_MONTGOMERY, Assert.Single(policy.Seen.OfType<KeyAgreementKeyRequest>()).KeyType);
        });
    }

    // Review Focus 5: a peer of the other Montgomery curve, or of another algorithm, never reaches the token.
    public static TheoryData<string> WrongCurvePeers => ["X448 peer", "Ed25519 peer", "P-256 peer"];

    [Theory]
    [MemberData(nameof(WrongCurvePeers))]
    public void X25519_WrongCurvePeer_ThrowsPkcs11ArgumentException(string peer)
    {
        using var p256 = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] spki = peer switch
        {
            "X448 peer" => MontgomerySpki("1.3.101.111", X448BobPublic),
            "Ed25519 peer" => MontgomerySpki("1.3.101.112", X25519BobPublic),
            _ => p256.ExportSubjectPublicKeyInfo(),
        };
        WithMontgomeryKey(X25519Oid, X25519Shared, OptIn(KeyMaterialExportKind.EcdhSharedSecret), (key, module) =>
        {
            Assert.Throws<Pkcs11ArgumentException>(() => key.DeriveRawSecret(spki));
            Assert.Null(module.DerivedWith);
        });
    }

    [Fact]
    public void X448_X25519Peer_ThrowsPkcs11ArgumentException() =>
        WithMontgomeryKey(X448Oid, X448Shared, OptIn(KeyMaterialExportKind.EcdhSharedSecret), (key, module) =>
        {
            Assert.Throws<Pkcs11ArgumentException>(() => key.DeriveRawSecret(MontgomerySpki("1.3.101.110", X25519BobPublic)));
            Assert.Null(module.DerivedWith);
        });

    // Review Focus 5: u = 0 is the low-order point every X25519/X448 secret with it is all zero for. X25519
    // ignores the top bit of the last byte (RFC 7748 §5), so 0x00…80 is u = 0 too.
    public static TheoryData<string, string> ZeroPeers => new()
    {
        { "X25519", new string('0', 64) },
        { "X25519", new string('0', 62) + "80" },
        { "X448", new string('0', 112) },
    };

    [Theory]
    [MemberData(nameof(ZeroPeers))]
    public void Montgomery_ZeroPeer_ThrowsPkcs11ArgumentException(string curve, string peerHex)
    {
        (byte[] ecParams, string oid, _, byte[] shared) = Curve(curve);
        WithMontgomeryKey(ecParams, shared, OptIn(KeyMaterialExportKind.EcdhSharedSecret), (key, module) =>
        {
            Assert.Throws<Pkcs11ArgumentException>(() => key.DeriveRawSecret(MontgomerySpki(oid, Convert.FromHexString(peerHex))));
            Assert.Null(module.DerivedWith);
        });
    }

    // RFC 7748 §6.1: the other low-order points also give an all-zero secret, and a token that does not check
    // returns it. It is refused, and the derived object is still destroyed.
    [Theory]
    [InlineData("X25519")]
    [InlineData("X448")]
    public void Montgomery_TokenReturnsAllZeroSecret_Throws(string curve)
    {
        (byte[] ecParams, string oid, byte[] peer, byte[] shared) = Curve(curve);
        WithMontgomeryKey(ecParams, new byte[shared.Length], OptIn(KeyMaterialExportKind.EcdhSharedSecret), (key, module) =>
        {
            Assert.Throws<Pkcs11ArgumentException>(() => key.DeriveRawSecret(MontgomerySpki(oid, peer)));
            Assert.Equal([3UL], module.Destroyed);
        });
    }

    [Fact]
    public void X25519_TokenReturnsShortSecret_ThrowsCryptographicException() =>
        WithMontgomeryKey(X25519Oid, X25519Shared[1..], OptIn(KeyMaterialExportKind.EcdhSharedSecret), (key, module) =>
        {
            Assert.Throws<CryptographicException>(() => key.DeriveRawSecret(MontgomerySpki("1.3.101.110", X25519BobPublic)));
            Assert.Equal([3UL], module.Destroyed);
        });

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(56)]
    public void X25519_PeerOfTheWrongLength_ThrowsPkcs11ArgumentException(int length) =>
        WithMontgomeryKey(X25519Oid, X25519Shared, OptIn(KeyMaterialExportKind.EcdhSharedSecret), (key, module) =>
        {
            byte[] peer = new byte[length];
            peer[0] = 9;
            Assert.Throws<Pkcs11ArgumentException>(() => key.DeriveRawSecret(MontgomerySpki("1.3.101.110", peer)));
            Assert.Null(module.DerivedWith);
        });

    // RFC 8410 §3: the parameters MUST be absent.
    [Fact]
    public void X25519_PeerWithParameters_ThrowsArgumentException() =>
        WithMontgomeryKey(X25519Oid, X25519Shared, OptIn(KeyMaterialExportKind.EcdhSharedSecret), (key, module) =>
        {
            Assert.Throws<ArgumentException>(() => key.DeriveRawSecret(MontgomerySpki("1.3.101.110", X25519BobPublic, withNullParameters: true)));
            Assert.Null(module.DerivedWith);
        });

    [Fact]
    public void X25519_PeerNotAnSpki_ThrowsArgumentException() =>
        WithMontgomeryKey(X25519Oid, X25519Shared, OptIn(KeyMaterialExportKind.EcdhSharedSecret), (key, module) =>
        {
            Assert.Throws<ArgumentException>(() => key.DeriveRawSecret(X25519BobPublic));
            Assert.Null(module.DerivedWith);
        });

    // A Montgomery key whose CKA_EC_PARAMS names neither curve: its field size is unknown, so nothing is derived.
    [Fact]
    public void Montgomery_UnknownLocalCurve_ThrowsPkcs11Exception() =>
        WithMontgomeryKey([0x06, 0x03, 0x2B, 0x65, 0x70], X25519Shared, OptIn(KeyMaterialExportKind.EcdhSharedSecret), (key, module) =>
        {
            Assert.ThrowsAny<Pkcs11Exception>(() => key.DeriveRawSecret(MontgomerySpki("1.3.101.110", X25519BobPublic)));
            Assert.Null(module.DerivedWith);
        });

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
