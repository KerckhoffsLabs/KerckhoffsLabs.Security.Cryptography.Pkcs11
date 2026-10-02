using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;
using BclECCurve = System.Security.Cryptography.ECCurve;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The read-back operations (<see cref="Pkcs11Key.DeriveAndExportSecret"/>,
/// <see cref="Pkcs11Workspace.DeriveAndExportSecret"/>, and the KEM pair) over the in-process
/// <c>ManagedSoftToken</c>: the closed mechanism list, the export request they submit, the waiver
/// that stays inside one call, the ephemeral key's lifetime, and the ECDH peer check.
/// </summary>
[NoBackendCollection("Drives a per-test ManagedSoftToken in process — no native module is loaded and " +
                     "the token holds no static state, so this is safe alongside every backend collection.")]
public sealed class SecretExportTests
{
    private const string Reason = "Reviewed for this test.";
    private static readonly byte[] BaseKeyBytes = [.. Enumerable.Range(0, 32).Select(i => (byte)(i + 1))];
    private static readonly byte[] Salt = "salt"u8.ToArray();
    private static readonly byte[] Info = "info"u8.ToArray();

    public static bool EcSupported { get; } = ProbeP256();

    private static bool ProbeP256()
    {
        try
        {
            using (ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256)) { }
            return true;
        }
        catch (Exception ex) when (ex is PlatformNotSupportedException or CryptographicException)
        {
            return false;
        }
    }

    private sealed class RecordingPolicy(ICryptoPolicy inner) : ICryptoPolicy
    {
        public List<PolicyRequest> Seen { get; } = [];
        public string Name => "Recording";
        public bool AllowsOverride => true;
        public PolicyDecision Evaluate(PolicyRequest request)
        {
            Seen.Add(request);
            return inner.Evaluate(request);
        }
    }

    /// <summary>Delegates to <paramref name="inner"/>, running <paramref name="onExport"/> when it judges the export itself.</summary>
    private sealed class OnExportPolicy(ICryptoPolicy inner, Action onExport) : ICryptoPolicy
    {
        public string Name => "OnExport";
        public bool AllowsOverride => true;
        public PolicyDecision Evaluate(PolicyRequest request)
        {
            if (request is SecretExportRequest)
                onExport();
            return inner.Evaluate(request);
        }
    }

    private static Pkcs11Key ImportHkdfKey(Pkcs11Workspace workspace)
    {
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).Value(BaseKeyBytes).Derive().Build();
        return workspace.ImportKey(template);
    }

    private static Mechanism Hkdf() =>
        new(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC, Salt, Info));

    private static byte[] ExpectedHkdf(int length) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, BaseKeyBytes, length, Salt, Info);

    // === KDF output ===========================================================================

    [Fact]
    public void Hkdf_UnderTheNarrowOptIn_ReturnsTheKdfOutput_AndDestroysTheEphemeralKey()
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build());
        using var key = ImportHkdfKey(workspace);
        int objectsBefore = token.ObjectCount;

        byte[] output = new byte[42];
        key.DeriveAndExportSecret(Hkdf(), output);

        Assert.Equal(ExpectedHkdf(42), output);
        Assert.Equal(objectsBefore, token.ObjectCount);
    }

    [Fact]
    public void Hkdf_UnderRecommended_IsRefusedAsAnExport_NamingTheMechanismAndBaseKey()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var key = ImportHkdfKey(workspace);
        byte[] output = new byte[32];

        var ex = Assert.Throws<CryptoPolicyViolationException>(() => key.DeriveAndExportSecret(Hkdf(), output));

        var request = Assert.IsType<SecretExportRequest>(ex.Request);
        Assert.Equal(SecretExportKind.KdfOutput, request.Kind);
        Assert.Equal(CKM.CKM_HKDF_DERIVE, request.Mechanism);
        Assert.Equal(CKO.CKO_SECRET_KEY, request.BaseKeyClass);
        Assert.Equal(CKK.CKK_GENERIC_SECRET, request.BaseKeyType);
        Assert.Contains("AllowSecretExport(SecretExportKind.KdfOutput, reason)", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EphemeralTemplate_StatesEveryRestriction_ButNotCkaModifiable()
    {
        using ReadOnlyDisposableList<ObjectAttribute> template = SecretExport.EphemeralTemplate(32);
        bool Flag(CKA type) => template.Single(a => a.Type == type).GetValueAsBool();

        Assert.False(Flag(CKA.CKA_TOKEN));
        Assert.False(Flag(CKA.CKA_SENSITIVE));
        Assert.True(Flag(CKA.CKA_EXTRACTABLE));
        Assert.False(Flag(CKA.CKA_COPYABLE));
        Assert.All([CKA.CKA_ENCRYPT, CKA.CKA_DECRYPT, CKA.CKA_SIGN, CKA.CKA_VERIFY, CKA.CKA_WRAP, CKA.CKA_UNWRAP, CKA.CKA_DERIVE],
            usage => Assert.False(Flag(usage)));
        Assert.Equal(32UL, template.Single(a => a.Type == CKA.CKA_VALUE_LEN).GetValueAsUlong());
        // SoftHSM refuses every attribute written after CKA_MODIFIABLE=false on C_DeriveKey.
        Assert.DoesNotContain(template, a => a.Type == CKA.CKA_MODIFIABLE);
    }

    [Fact]
    public void AllowedExport_DoesNotSubmitTheEphemeralTemplate_ButStillJudgesTheMechanism()
    {
        var policy = new RecordingPolicy(CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build());
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, policy);
        using var key = ImportHkdfKey(workspace);
        policy.Seen.Clear();

        key.DeriveAndExportSecret(Hkdf(), new byte[32]);

        Assert.Single(policy.Seen.OfType<SecretExportRequest>());
        Assert.Contains(policy.Seen, r => r is MechanismUseRequest { Operation: CryptoOperation.Derive });
        Assert.Empty(policy.Seen.OfType<KeyTemplateRequest>());
    }

    [Fact]
    public void TheWaiver_EndsWithTheCall()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build());
        using var key = ImportHkdfKey(workspace);
        key.DeriveAndExportSecret(Hkdf(), new byte[32]);

        using var readable = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Sensitive(false).Extractable().Build();
        var ex = Assert.Throws<CryptoPolicyViolationException>(() => key.Derive(Hkdf(), readable));

        Assert.IsType<KeyTemplateRequest>(ex.Request);
    }

    [Fact]
    public void AllowedExport_IsLoggedWithTheMechanism()
    {
        var logger = new CapturingLogger();
        using var library = new Pkcs11Library(new ManagedSoftToken(), new CapturingLoggerFactory(logger));
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build());
        using var key = ImportHkdfKey(workspace);

        key.DeriveAndExportSecret(Hkdf(), new byte[32]);

        var entry = Assert.Single(logger.Entries, e => e.Message.Contains("allowed export", StringComparison.Ordinal));
        Assert.Equal(Microsoft.Extensions.Logging.LogLevel.Information, entry.Level);
        Assert.Contains("KdfOutput", entry.Message, StringComparison.Ordinal);
        Assert.Contains("CKM_HKDF_DERIVE", entry.Message, StringComparison.Ordinal);
    }

    // The ephemeral key is extractable and non-sensitive for its short life: no other caller may use the
    // session from the export decision until it is destroyed, or it could find and read the key.
    [Fact]
    public void TheSession_IsHeldFromTheExportDecisionToTheDestroy()
    {
        using var library = ManagedToken.NewLibrary();
        Pkcs11Workspace? workspace = null;
        Exception? other = null;
        var policy = new OnExportPolicy(
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build(),
            () =>
            {
                var thread = new Thread(() =>
                {
                    try { workspace!.GenerateRandom(1); }
                    catch (Exception ex) { other = ex; }
                });
                thread.Start();
                thread.Join();
            });
        using (workspace = ManagedToken.OpenWorkspace(library, policy))
        {
            using var key = ImportHkdfKey(workspace);

            key.DeriveAndExportSecret(Hkdf(), new byte[32]);
        }

        Assert.IsType<InvalidOperationException>(other);
    }

    // The policy that allowed the export decides the whole read-back: a lease that changes the effective
    // policy midway must not leave the waived steps judged by a policy that never allowed the export.
    [Fact]
    public void TheExportingPolicy_DecidesTheWholeReadBack()
    {
        using var library = ManagedToken.NewLibrary();
        Pkcs11Workspace? workspace = null;
        IDisposable? lease = null;
        var allowing = CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build();
        var policy = new OnExportPolicy(allowing, () => lease ??= workspace!.UsePolicy(new CryptoPolicyBuilder("DenyAll").Build()));
        using (workspace = ManagedToken.OpenWorkspace(library, policy))
        {
            using var key = ImportHkdfKey(workspace);
            byte[] output = new byte[42];

            key.DeriveAndExportSecret(Hkdf(), output);

            Assert.Equal(ExpectedHkdf(42), output);
            lease!.Dispose();
        }
    }

    // The audit line records secrets that actually left the token: a read-back the export decision allowed
    // but a later check refused, or the token failed, logs no "allowed export".
    [Fact]
    public void ExportRefusedAfterTheDecision_IsNotLoggedAsAnAllowedExport()
    {
        var logger = new CapturingLogger();
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token, new CapturingLoggerFactory(logger));
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build());
        using var key = ImportHkdfKey(workspace);

        token.SensitiveAttribute = CKA.CKA_VALUE;
        try
        {
            Assert.Throws<CryptographicException>(() => key.DeriveAndExportSecret(Hkdf(), new byte[32]));
        }
        finally
        {
            token.SensitiveAttribute = null;
        }

        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("allowed export", StringComparison.Ordinal));
    }

    // The waiver an export grants the session's create calls (template and CKD_NULL judgement) and the audit line
    // hold only inside the read-back scope that decided the export.
    [Fact]
    public void ExportWaiver_OutsideAnExportScope_IsRefused()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportHkdfKey(workspace);

        Assert.Throws<InvalidOperationException>(() =>
            workspace.Session.DeriveKey(Hkdf(), key.PrivateHandle, [], SecretExportKind.KdfOutput));
        Assert.Throws<InvalidOperationException>(() =>
            workspace.Session.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), [], SecretExportKind.KdfOutput));
        Assert.Throws<InvalidOperationException>(() => workspace.Session.LogExported());
    }

    // The ephemeral key exists from its creation to its destruction; the session must be held for that whole
    // window, not only at the export decision.
    [Fact]
    public void TheSession_IsHeld_WhileTheEphemeralKeyExists()
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build());
        using var key = ImportHkdfKey(workspace);
        int objects = token.ObjectCount;
        bool probed = false;
        Exception? other = null;
        token.BeforeGetAttributeValue = () =>
        {
            if (probed || token.ObjectCount == objects)
                return;                                          // only once the ephemeral key exists
            probed = true;
            var thread = new Thread(() =>
            {
                try { workspace.GenerateRandom(1); }
                catch (Exception ex) { other = ex; }
            });
            thread.Start();
            thread.Join();
        };
        try
        {
            key.DeriveAndExportSecret(Hkdf(), new byte[32]);
        }
        finally
        {
            token.BeforeGetAttributeValue = null;
        }

        Assert.True(probed);
        Assert.IsType<InvalidOperationException>(other);
    }

    // Every read-back path writes exactly one audit line, so dropping the scope from one would show.
    [Theory]
    [InlineData("hkdf")]
    [InlineData("sp800-108")]
    [InlineData("pbkdf2")]
    public void EachReadBack_LogsExactlyOneAllowedExport(string path)
    {
        var logger = new CapturingLogger();
        using var library = new Pkcs11Library(new ManagedSoftToken(), new CapturingLoggerFactory(logger));
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportHkdfKey(workspace);
        using var password = new SecurePassword("placeholder-password"u8);

        switch (path)
        {
            case "hkdf":
                key.DeriveAndExportSecret(Hkdf(), new byte[32]);
                break;
            case "sp800-108":
                key.DeriveAndExportSecret(new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF,
                    CkmSp800108KdfParams.CounterModeHmac(CKM.CKM_SHA256_HMAC, "label"u8, "context"u8)), new byte[32]);
                break;
            default:
                workspace.DeriveAndExportSecret(Pbkdf2(password), new byte[32]);
                break;
        }

        Assert.Single(logger.Entries, e => e.Message.Contains("allowed export", StringComparison.Ordinal));
    }

    [Fact(SkipUnless = nameof(EcSupported), Skip = "Requires " + nameof(EcSupported))]
    public void EcdhReadBack_LogsExactlyOneAllowedExport()
    {
        var logger = new CapturingLogger();
        using var library = new Pkcs11Library(new ManagedSoftToken(), new CapturingLoggerFactory(logger));
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var peer = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

        key.DeriveAndExportSecret(
            new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL, peer.ExportParameters(false))), new byte[32]);

        Assert.Single(logger.Entries, e => e.Message.Contains("allowed export", StringComparison.Ordinal));
    }

    // The raw ECDH read-back waives the CKD_NULL judgement; that waiver must follow the policy that allowed the
    // export, even when a lease changes the effective policy mid read-back.
    [Fact(SkipUnless = nameof(EcSupported), Skip = "Requires " + nameof(EcSupported))]
    public void TheExportingPolicy_DecidesTheRawEcdhReadBack()
    {
        using var library = ManagedToken.NewLibrary();
        Pkcs11Workspace? workspace = null;
        IDisposable? lease = null;
        var allowing = CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.EcdhSharedSecret, Reason).Build();
        var policy = new OnExportPolicy(allowing, () => lease ??= workspace!.UsePolicy(new CryptoPolicyBuilder("DenyAll").Build()));
        using (workspace = ManagedToken.OpenWorkspace(library, policy))
        {
            using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
            using var peer = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
            byte[] ours = new byte[32];

            key.DeriveAndExportSecret(
                new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL, peer.ExportParameters(false))), ours);

            using var bclKey = ECDiffieHellman.Create(key.ExportEcPublicParameters());
            Assert.Equal(peer.DeriveRawSecretAgreement(bclKey.PublicKey), ours);
            lease!.Dispose();
        }
    }

    [Fact]
    public void FailedDestroy_ZeroesTheDestination_AndSurfacesTheTokensCode()
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build());
        using var key = ImportHkdfKey(workspace);
        byte[] output = new byte[32];

        token.DestroyObjectResultOverride = CKR.CKR_FUNCTION_FAILED;
        try
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.DeriveAndExportSecret(Hkdf(), output));
            Assert.Equal(CKR.CKR_FUNCTION_FAILED, ex.ReturnValue);
        }
        finally
        {
            token.DestroyObjectResultOverride = null;
        }

        Assert.All(output, b => Assert.Equal(0, b));
    }

    // A secret is never handed back alongside an exception: each read failure zeroes the destination and
    // still destroys the ephemeral key.
    [Fact]
    public void UnreadableValue_ThrowsCryptographicException_ZeroesTheDestination_AndDestroysTheKey()
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build());
        using var key = ImportHkdfKey(workspace);
        int objects = token.ObjectCount;
        byte[] output = [.. Enumerable.Repeat((byte)0xAA, 32)];

        token.SensitiveAttribute = CKA.CKA_VALUE;
        try
        {
            Assert.Throws<CryptographicException>(() => key.DeriveAndExportSecret(Hkdf(), output));
        }
        finally
        {
            token.SensitiveAttribute = null;
        }

        Assert.All(output, b => Assert.Equal(0, b));
        Assert.Equal(objects, token.ObjectCount);
    }

    [Fact]
    public void ValueOfAnotherLength_ThrowsCryptographicException_ZeroesTheDestination_AndDestroysTheKey()
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build());
        using var key = ImportHkdfKey(workspace);
        int objects = token.ObjectCount;
        byte[] output = [.. Enumerable.Repeat((byte)0xAA, 32)];

        token.ValueTruncation = 16;
        try
        {
            var ex = Assert.Throws<CryptographicException>(() => key.DeriveAndExportSecret(Hkdf(), output));
            Assert.Contains("16-byte", ex.Message);
        }
        finally
        {
            token.ValueTruncation = null;
        }

        Assert.All(output, b => Assert.Equal(0, b));
        Assert.Equal(objects, token.ObjectCount);
    }

    [Fact]
    public void ReadAndDestroyBothFailing_SurfaceTheReadsCode_AndZeroTheDestination()
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build());
        using var key = ImportHkdfKey(workspace);
        byte[] output = [.. Enumerable.Repeat((byte)0xAA, 32)];

        token.GetAttributeValueResultOverride = CKR.CKR_DEVICE_ERROR;
        token.DestroyObjectResultOverride = CKR.CKR_FUNCTION_FAILED;
        try
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.DeriveAndExportSecret(Hkdf(), output));
            Assert.Equal(CKR.CKR_DEVICE_ERROR, ex.ReturnValue);
        }
        finally
        {
            token.GetAttributeValueResultOverride = null;
            token.DestroyObjectResultOverride = null;
        }

        Assert.All(output, b => Assert.Equal(0, b));
    }

    // The CKD_NULL waiver covers the raw-secret read-back only: any other KDF in the parameters is still judged
    // by the session, even under the EcdhSharedSecret opt-in.
    [Fact(SkipUnless = nameof(EcSupported), Skip = "Requires " + nameof(EcSupported))]
    public void Ecdh_ReadBackWithAnotherKdf_StillHasItsKdfJudged()
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.EcdhSharedSecret, Reason).Build());
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var peer = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForPeer(CKD.CKD_SHA1_KDF, peer.ExportParameters(false)));
        int objects = token.ObjectCount;

        var ex = Assert.Throws<CryptoPolicyViolationException>(() => key.DeriveAndExportSecret(mechanism, new byte[32]));

        Assert.IsType<KeyAgreementKdfRequest>(ex.Request);
        Assert.Equal(objects, token.ObjectCount);
    }

    [Theory]
    [InlineData(CKM.CKM_XOR_BASE_AND_DATA)]
    [InlineData(CKM.CKM_CONCATENATE_BASE_AND_KEY)]
    [InlineData(CKM.CKM_EXTRACT_KEY_FROM_KEY)]
    [InlineData(CKM.CKM_AES_ECB_ENCRYPT_DATA)]
    [InlineData(CKM.CKM_HKDF_DATA)]
    public void MechanismsOutsideTheList_AreRefused_WhateverThePolicy(CKM mechanism)
    {
        var policy = new RecordingPolicy(CryptoPolicy.AllowInsecure);
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, policy);
        using var key = ImportHkdfKey(workspace);
        policy.Seen.Clear();

        var ex = Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(new Mechanism(mechanism), new byte[32]));

        Assert.Equal("mechanism", ex.ParamName);
        Assert.Empty(policy.Seen);
    }

    // A second key fed into the PRF input would be read back through the output: with a CMAC PRF and a
    // base key of known value, T(1) = CMAC(base, victim || …) decrypts back to the victim key's value.
    [Theory]
    [InlineData(CKM.CKM_SP800_108_COUNTER_KDF)]
    [InlineData(CKM.CKM_SP800_108_FEEDBACK_KDF)]
    [InlineData(CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF)]
    public void Sp800108WithAKeySegment_IsRefused_WhateverThePolicy(CKM mode)
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportHkdfKey(workspace);
        using var victim = ImportHkdfKey(workspace);
        Sp800108KdfBuilder builder = mode switch
        {
            CKM.CKM_SP800_108_COUNTER_KDF => CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC),
            CKM.CKM_SP800_108_FEEDBACK_KDF => CkmSp800108KdfParams.Feedback(CKM.CKM_SHA256_HMAC),
            _ => CkmSp800108KdfParams.DoublePipeline(CKM.CKM_SHA256_HMAC),
        };
        var mechanism = new Mechanism(mode, builder.Key(victim).IterationCounter().Build());
        int objects = token.ObjectCount;

        var ex = Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(mechanism, new byte[32]));

        Assert.Equal("mechanism", ex.ParamName);
        Assert.Contains("key segment", ex.Message);
        Assert.Equal(objects, token.ObjectCount);
    }

    // HKDF-Extract with a key as the salt computes HMAC(saltKey, base): read back, it is a MAC under a key
    // the export decision never saw.
    [Fact]
    public void HkdfWithASaltKey_IsRefused_WhateverThePolicy()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportHkdfKey(workspace);
        using var saltKey = ImportHkdfKey(workspace);
        var mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE,
            CkmHkdfParams.WithSaltKey(HkdfOperation.ExtractOnly, CKM.CKM_SHA256_HMAC, saltKey));

        var ex = Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(mechanism, new byte[32]));

        Assert.Equal("mechanism", ex.ParamName);
        Assert.Contains("salt key", ex.Message);
    }

    // A mechanism sent to the wrong read-back names the one that takes it.
    [Fact]
    public void WrongEntryPoint_NamesTheReadBackThatTakesTheMechanism()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportHkdfKey(workspace);
        using var password = new SecurePassword("placeholder-password"u8);

        Assert.Contains("Pkcs11Workspace.DeriveAndExportSecret", Assert.Throws<ArgumentException>(() =>
            key.DeriveAndExportSecret(Pbkdf2(password), new byte[32])).Message);
#pragma warning disable KLPKCS11501
        Assert.Contains("EncapsulateAndExportSecret", Assert.Throws<ArgumentException>(() =>
            key.DeriveAndExportSecret(new Mechanism(CKM.CKM_ML_KEM), new byte[32])).Message);
        Assert.Contains("Pkcs11Key.DeriveAndExportSecret", Assert.Throws<ArgumentException>(() =>
            key.DecapsulateAndExportSecret(Hkdf(), new byte[1088], new byte[32])).Message);
#pragma warning restore KLPKCS11501
        Assert.Contains("Pkcs11Key.DeriveAndExportSecret", Assert.Throws<ArgumentException>(() =>
            workspace.DeriveAndExportSecret(Hkdf(), new byte[32])).Message);
    }

    // A supported mechanism in the wrong shape says what is wrong with it.
    // By name, so each case is serializable and listed on its own.
    private static Mechanism WrongShape(string shape) => shape switch
    {
        "ecdh-without-params" => new Mechanism(CKM.CKM_ECDH1_DERIVE),
        "ecdh-without-peer" => new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForEncapsulation(CKD.CKD_NULL)),
        "hkdf-without-params" => new Mechanism(CKM.CKM_HKDF_DERIVE),
        "sp800-108-without-params" => new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF),
        _ => throw new ArgumentOutOfRangeException(nameof(shape)),
    };

    [Theory]
    [InlineData("ecdh-without-params", "requires CkmEcdh1DeriveParams")]
    [InlineData("ecdh-without-peer", "peer's public point")]
    [InlineData("hkdf-without-params", "requires CkmHkdfParams")]
    [InlineData("sp800-108-without-params", "requires CkmSp800108KdfParams")]
    public void WrongShape_SaysWhatIsWrong(string shape, string expected)
    {
        Mechanism mechanism = WrongShape(shape);
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportHkdfKey(workspace);

        var ex = Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(mechanism, new byte[32]));

        Assert.Equal("mechanism", ex.ParamName);
        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public void Pbkdf2WithoutItsParameters_SaysWhatIsWrong()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);

        Assert.Contains("requires CkmPkcs5Pbkd2Params", Assert.Throws<ArgumentException>(() =>
            workspace.DeriveAndExportSecret(new Mechanism(CKM.CKM_PKCS5_PBKD2), new byte[32])).Message);
    }

    [Fact]
    public void Sp800108WithAdditionalDerivedKeys_IsRefused()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportHkdfKey(workspace);
        using var sibling = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(16).Build();
        var mechanism = new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC)
            .IterationCounter().ByteArray("label"u8.ToArray())
            .DkmLength(Sp800108DkmLengthMethod.SumOfKeys)
            .AddDerivedKey([.. sibling.Attributes])
            .Build());

        var ex = Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(mechanism, new byte[32]));

        Assert.Equal("mechanism", ex.ParamName);
        Assert.Contains("additional keys", ex.Message);
    }

    [Fact]
    public void Sp800108Counter_MatchesTheBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build());
        using var key = ImportHkdfKey(workspace);
        byte[] output = new byte[32];

        key.DeriveAndExportSecret(new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF,
            CkmSp800108KdfParams.CounterModeHmac(CKM.CKM_SHA256_HMAC, "label"u8, "context"u8)), output);

        Assert.Equal(SP800108HmacCounterKdf.DeriveBytes(BaseKeyBytes, HashAlgorithmName.SHA256, "label"u8, "context"u8, 32), output);
    }

    [Fact]
    public void EmptyDestination_IsRefused()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportHkdfKey(workspace);

        var ex = Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(Hkdf(), []));

        Assert.Equal("destination", ex.ParamName);
    }

    // === Password-based KDF ===================================================================

    private static Mechanism Pbkdf2(SecurePassword password) =>
        new(CKM.CKM_PKCS5_PBKD2, new CkmPkcs5Pbkd2Params(Salt, 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, password));

    [Fact]
    public void Pbkdf2_UnderItsOwnOptIn_MatchesTheBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.PasswordKdfOutput, Reason).Build());
        using var password = new SecurePassword("placeholder-password"u8);
        byte[] output = new byte[32];

        workspace.DeriveAndExportSecret(Pbkdf2(password), output);

        Assert.Equal(Rfc2898DeriveBytes.Pbkdf2("placeholder-password"u8, Salt, 1000, HashAlgorithmName.SHA256, 32), output);
    }

    [Fact]
    public void Pbkdf2_IsNotCoveredByTheKeyKdfOptIn()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KdfOutput, Reason).Build());
        using var password = new SecurePassword("placeholder-password"u8);

        var ex = Assert.Throws<CryptoPolicyViolationException>(() => workspace.DeriveAndExportSecret(Pbkdf2(password), new byte[32]));

        var request = Assert.IsType<SecretExportRequest>(ex.Request);
        Assert.Equal(SecretExportKind.PasswordKdfOutput, request.Kind);
        Assert.Null(request.BaseKeyClass);
        Assert.Null(request.BaseKeyType);
    }

    [Fact]
    public void WorkspaceDerive_RefusesAnythingButPbkdf2()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);

        var ex = Assert.Throws<ArgumentException>(() =>
            workspace.DeriveAndExportSecret(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), new byte[32]));

        Assert.Equal("mechanism", ex.ParamName);
    }

    // === ECDH =================================================================================

    [Fact(SkipUnless = nameof(EcSupported), Skip = "Requires " + nameof(EcSupported))]
    public void Ecdh_RawSecret_UnderItsOptIn_MatchesTheBcl_WithoutACkdNullOptIn()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.EcdhSharedSecret, Reason).Build());
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var peer = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        byte[] z = new byte[32];

        key.DeriveAndExportSecret(
            new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL, peer.ExportParameters(false))), z);

        using var local = ECDiffieHellman.Create(key.ExportEcPublicParameters());
        Assert.Equal(peer.DeriveRawSecretAgreement(local.PublicKey), z);
    }

    [Fact(SkipUnless = nameof(EcSupported), Skip = "Requires " + nameof(EcSupported))]
    public void Ecdh_OffCurvePeerPoint_IsRefusedBeforeTheToken()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.EcdhSharedSecret, Reason).Build());
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        var ex = Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(
            new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL, OffCurveP256())), new byte[32]));

        Assert.Equal("mechanism", ex.ParamName);
    }

    [Fact(SkipUnless = nameof(EcSupported), Skip = "Requires " + nameof(EcSupported))]
    public void Ecdh_PeerPointOfAnotherSize_IsRefused()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.EcdhSharedSecret, Reason).Build());
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var p384 = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP384);

        Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(
            new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL, p384.ExportParameters(false))), new byte[32]));
    }

    private static ECParameters OffCurveP256() => new()
    {
        Curve = BclECCurve.NamedCurves.nistP256,
        Q = new ECPoint { X = new byte[32], Y = [.. Enumerable.Repeat((byte)1, 32)] },
    };

    [Fact(SkipUnless = nameof(EcSupported), Skip = "Requires " + nameof(EcSupported))]
    public void Ecdh_RawSecret_RequiresADestinationOfTheFieldSize()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.EcdhSharedSecret, Reason).Build());
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var peer = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL, peer.ExportParameters(false)));

        var ex = Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(mechanism, new byte[31]));

        Assert.Equal("destination", ex.ParamName);
    }

    [Fact(SkipUnless = nameof(EcSupported), Skip = "Requires " + nameof(EcSupported))]
    public void Ecdh_PeerNamingAnotherCurve_IsRefused_EvenWhenItsPointHasTheRightSize()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var peer = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
        ECParameters claimed = peer.ExportParameters(false);
        claimed.Curve = BclECCurve.CreateFromValue("1.3.36.3.3.2.8.1.1.7"); // brainpoolP256r1: same size, other curve

        var ex = Assert.Throws<ArgumentException>(() => workspace.DeriveSharedSecretEcdh(key, claimed));

        Assert.Equal("peerPublicKey", ex.ParamName);
        Assert.Contains("expected", ex.Message, StringComparison.Ordinal);
    }

    // Every ECDH derivation checks the peer, not only the read-back: the invalid-curve attack works as
    // well when the derived key stays on the token.
    [Fact(SkipUnless = nameof(EcSupported), Skip = "Requires " + nameof(EcSupported))]
    public void Ecdh_OffCurvePeer_IsRefusedOnEveryDerivationPath()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        byte[] offCurvePoint = CkmEcdh1DeriveParams.ForPeer(CKD.CKD_SHA256_KDF, OffCurveP256()).PublicData.ToArray();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Encrypt().Decrypt().Build();

        var derive = Assert.Throws<ArgumentException>(() => key.Derive(
            new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, offCurvePoint)), template));
        var rawSpan = Assert.Throws<ArgumentException>(() => workspace.DeriveSharedSecretEcdh(key, offCurvePoint));
        var parameters = Assert.Throws<ArgumentException>(() => workspace.DeriveSharedSecretEcdh(key, OffCurveP256()));

        Assert.Equal("mechanism", derive.ParamName);
        Assert.Equal("peerPublicPoint", rawSpan.ParamName);
        Assert.Equal("peerPublicKey", parameters.ParamName);
    }

    [Fact]
    public void Ecdh_ForEncapsulationParameters_AreNotAPeerDerivation()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportHkdfKey(workspace);

        Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(
            new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForEncapsulation(CKD.CKD_NULL)), new byte[32]));
    }

    // === KEM ==================================================================================

#pragma warning disable KLPKCS11501 // The KEM read-back is what is under test.
    [Fact]
    public void Kem_OnlyMlKemIsAccepted()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportHkdfKey(workspace);

        // The v3.2 KEM functions also accept RSA PKCS#1 v1.5, whose decapsulated output must never be read.
#pragma warning disable KLPKCS11008
        var rsaPkcs = new Mechanism(CKM.CKM_RSA_PKCS);
#pragma warning restore KLPKCS11008
        Assert.Throws<ArgumentException>(() => key.EncapsulateAndExportSecret(rsaPkcs, new byte[256], new byte[32]));
        Assert.Throws<ArgumentException>(() => key.DecapsulateAndExportSecret(rsaPkcs, new byte[256], new byte[32]));
    }

    // Every ML-KEM parameter set has a 32-byte shared secret (FIPS 203). Another length would reach the
    // token as CKA_VALUE_LEN, and a token that honours it would hand back a truncated secret.
    [Theory]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    public void Kem_SharedSecretOtherThan32Bytes_IsRefused_BeforeTheToken(int length)
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportHkdfKey(workspace);
        var mlKem = new Mechanism(CKM.CKM_ML_KEM);
        int objects = token.ObjectCount;

        Assert.Equal("sharedSecret", Assert.Throws<ArgumentException>(() =>
            key.EncapsulateAndExportSecret(mlKem, new byte[1088], new byte[length])).ParamName);
        Assert.Equal("sharedSecret", Assert.Throws<ArgumentException>(() =>
            key.DecapsulateAndExportSecret(mlKem, new byte[1088], new byte[length])).ParamName);
        Assert.Equal(objects, token.ObjectCount);
    }

    // SoftHSM refuses CKA_VALUE_LEN on C_DecapsulateKey. The first decapsulation against a library tries the
    // conventional template, falls back without it on CKR_ATTRIBUTE_READ_ONLY, and remembers which form worked.
    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Kem_Decapsulate_FallsBackWithoutValueLen_AndRemembersIt()
    {
        var token = new ManagedSoftToken { DecapsulateRejectsValueLen = true };
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KemSharedSecret, Reason).Build());
        using var key = GenerateMlKem768(workspace);
        byte[] ciphertext = new byte[1088];
        byte[] sent = new byte[32];
        int written = key.EncapsulateAndExportSecret(new Mechanism(CKM.CKM_ML_KEM), ciphertext, sent);

        byte[] first = new byte[32];
        key.DecapsulateAndExportSecret(new Mechanism(CKM.CKM_ML_KEM), ciphertext.AsSpan(0, written), first);
        Assert.Equal(2, token.DecapsulateCalls);           // refused with CKA_VALUE_LEN, then accepted without
        Assert.True(library.MlKemDecapsulateOmitsValueLen);

        byte[] second = new byte[32];
        key.DecapsulateAndExportSecret(new Mechanism(CKM.CKM_ML_KEM), ciphertext.AsSpan(0, written), second);
        Assert.Equal(3, token.DecapsulateCalls);           // straight to the remembered form

        Assert.Equal(sent, first);
        Assert.Equal(sent, second);
    }

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Kem_Decapsulate_KeepsValueLen_WhenTheTokenAcceptsIt()
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KemSharedSecret, Reason).Build());
        using var key = GenerateMlKem768(workspace);
        byte[] ciphertext = new byte[1088];
        int written = key.EncapsulateAndExportSecret(new Mechanism(CKM.CKM_ML_KEM), ciphertext, new byte[32]);

        key.DecapsulateAndExportSecret(new Mechanism(CKM.CKM_ML_KEM), ciphertext.AsSpan(0, written), new byte[32]);

        Assert.Equal(1, token.DecapsulateCalls);
        Assert.False(library.MlKemDecapsulateOmitsValueLen);
    }

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void KemReadBacks_LogExactlyOneAllowedExportEach()
    {
        var logger = new CapturingLogger();
        using var library = new Pkcs11Library(new ManagedSoftToken(), new CapturingLoggerFactory(logger));
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KemSharedSecret, Reason).Build());
        using var key = GenerateMlKem768(workspace);
        byte[] ciphertext = new byte[1088];

        int written = key.EncapsulateAndExportSecret(new Mechanism(CKM.CKM_ML_KEM), ciphertext, new byte[32]);
        Assert.Single(logger.Entries, e => e.Message.Contains("allowed export", StringComparison.Ordinal));

        key.DecapsulateAndExportSecret(new Mechanism(CKM.CKM_ML_KEM), ciphertext.AsSpan(0, written), new byte[32]);
        Assert.Equal(2, logger.Entries.Count(e => e.Message.Contains("allowed export", StringComparison.Ordinal)));
    }

    private static Pkcs11Key GenerateMlKem768(Pkcs11Workspace workspace)
    {
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlKem.CKP_ML_KEM_768).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM).Attribute(CKA.CKA_DECAPSULATE, true).Build();
        return workspace.GenerateKeyPair(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), pubTpl, privTpl);
    }

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Kem_RoundTrips_UnderItsOptIn()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.KemSharedSecret, Reason).Build());
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlKem.CKP_ML_KEM_768).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM).Attribute(CKA.CKA_DECAPSULATE, true).Build();
        using var key = workspace.GenerateKeyPair(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), pubTpl, privTpl);

        byte[] ciphertext = new byte[1088];
        byte[] sent = new byte[32];
        int written = key.EncapsulateAndExportSecret(new Mechanism(CKM.CKM_ML_KEM), ciphertext, sent);
        byte[] received = new byte[32];
        key.DecapsulateAndExportSecret(new Mechanism(CKM.CKM_ML_KEM), ciphertext.AsSpan(0, written), received);

        Assert.Equal(1088, written);
        Assert.Equal(sent, received);
    }
#pragma warning restore KLPKCS11501

    // === Policy helpers =======================================================================

    [Fact]
    public void EnsurePermitted_ThrowsAndLogs_WhenRefused()
    {
        var logger = new CapturingLogger();
        using var library = new Pkcs11Library(new ManagedSoftToken(), new CapturingLoggerFactory(logger));
        using var workspace = ManagedToken.OpenWorkspace(library);
        var request = new HashUseRequest(new HashAlgorithmName("SHA224"), CryptoOperation.Sign);

        Assert.False(workspace.IsPermitted(request));
        Assert.Throws<CryptoPolicyViolationException>(() => workspace.EnsurePermitted(request));
        Assert.Contains(logger.Entries, e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning
            && e.Message.Contains("refused", StringComparison.Ordinal));
        Assert.Throws<ArgumentNullException>(() => workspace.EnsurePermitted(null!));
    }

    // A key answers policy questions itself, so code handed only a key cannot reach its workspace — and
    // through it UsePolicy, Dispose or key generation.
    [Fact]
    public void Key_AnswersPolicyQuestions_WithoutExposingItsWorkspace()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var key = ImportHkdfKey(workspace);
        var refused = new HashUseRequest(new HashAlgorithmName("SHA224"), CryptoOperation.Sign);
        var allowed = new HashUseRequest(HashAlgorithmName.SHA256, CryptoOperation.Sign);

        Assert.False(key.IsPermitted(refused));
        Assert.True(key.IsPermitted(allowed));
        Assert.Throws<CryptoPolicyViolationException>(() => key.EnsurePermitted(refused));
        key.EnsurePermitted(allowed);
        Assert.Throws<ArgumentNullException>(() => key.IsPermitted(null!));
        Assert.Null(typeof(Pkcs11Key).GetProperty("Workspace", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance));
    }

    // The export request reports the base key's class; a Montgomery or DH key is a private key.
    [Theory]
    [InlineData(CKK.CKK_EC_MONTGOMERY)]
    [InlineData(CKK.CKK_DH)]
    [InlineData(CKK.CKK_X9_42_DH)]
    public void ExportRequest_ReportsAKeyAgreementKey_AsAPrivateKey(CKK keyType)
    {
        var policy = new RecordingPolicy(CryptoPolicy.AllowInsecure);
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, policy);
        using var template = ObjectTemplate.ForPrivateKey(keyType).Derive().Build();
        using var key = workspace.ImportKey(template);
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, new byte[32]));

        Assert.ThrowsAny<Exception>(() => key.DeriveAndExportSecret(mechanism, new byte[32]));

        var request = Assert.IsType<SecretExportRequest>(policy.Seen.First(r => r is SecretExportRequest));
        Assert.Equal(CKO.CKO_PRIVATE_KEY, request.BaseKeyClass);
    }

    // A coordinate longer than any curve's is an argument error, not an arithmetic overflow.
    [Fact]
    public void ForPeer_RejectsCoordinatesLongerThanAnyCurve()
    {
        var parameters = new ECParameters { Q = new ECPoint { X = new byte[128], Y = new byte[128] } };

        Assert.Equal("peerPublicKey", Assert.Throws<ArgumentException>(() =>
            CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL, parameters)).ParamName);
    }

    // === X25519 / X448 =======================================================================
    // ManagedSoftToken has no Montgomery arithmetic (the BCL has none); its stand-in output tests the
    // library's checks and plumbing. The real agreement is tested against Kryoptic and NSS (X25519ReadBackTestCases).

    private static readonly byte[] X25519Oid = [0x06, 0x03, 0x2B, 0x65, 0x6E];                              // 1.3.101.110
    private static readonly byte[] X448Oid = [0x06, 0x03, 0x2B, 0x65, 0x6F];                                // 1.3.101.111
    private static readonly byte[] Curve25519Name = [0x13, 0x0A, .. "curve25519"u8];                        // PrintableString
    private static readonly byte[] PrivateValue = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    private static Pkcs11Key ImportMontgomeryKey(Pkcs11Workspace workspace, byte[] ecParams)
    {
        using var template = ObjectTemplate.ForPrivateKey(CKK.CKK_EC_MONTGOMERY)
            .Attribute(CKA.CKA_EC_PARAMS, ecParams).Attribute(CKA.CKA_VALUE, PrivateValue).Attribute(CKA.CKA_DERIVE, true).Build();
        return workspace.ImportKey(template);
    }

    private static Pkcs11Workspace OpenEcdhExportWorkspace(Pkcs11Library library) =>
        ManagedToken.OpenWorkspace(library,
            CryptoPolicy.Recommended.ToBuilder("Test").AllowSecretExport(SecretExportKind.EcdhSharedSecret, Reason).Build());

    private static Mechanism RawEcdh(byte[] peer) => new(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, peer));

    private static byte[] StandIn(byte[] u) => SHA512.HashData([.. PrivateValue, .. u])[..u.Length];

    public static TheoryData<byte[]> X25519Params => [X25519Oid, Curve25519Name];

    [Theory]
    [MemberData(nameof(X25519Params))]
    public void X25519_ReadBack_ReturnsTheTokensSecret(byte[] ecParams)
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = OpenEcdhExportWorkspace(library);
        using var key = ImportMontgomeryKey(workspace, ecParams);
        byte[] u = [.. Enumerable.Range(100, 32).Select(i => (byte)i)];
        int objects = token.ObjectCount;
        byte[] secret = new byte[32];

        key.DeriveAndExportSecret(RawEcdh(u), secret);

        Assert.Equal(StandIn(u), secret);
        Assert.Equal(objects, token.ObjectCount);
    }

    [Fact]
    public void X25519_AcceptsAPeerWrappedAsAnOctetString()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenEcdhExportWorkspace(library);
        using var key = ImportMontgomeryKey(workspace, X25519Oid);
        byte[] u = [.. Enumerable.Range(100, 32).Select(i => (byte)i)];
        byte[] secret = new byte[32];

        key.DeriveAndExportSecret(RawEcdh([0x04, 0x20, .. u]), secret);

        Assert.Equal(StandIn(u), secret);
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(56)]
    public void X25519_PeerOfAnotherLength_IsRefused_BeforeTheToken(int length)
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = OpenEcdhExportWorkspace(library);
        using var key = ImportMontgomeryKey(workspace, X25519Oid);
        int objects = token.ObjectCount;

        var ex = Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(RawEcdh([.. Enumerable.Repeat((byte)7, length)]), new byte[32]));

        Assert.Equal("mechanism", ex.ParamName);
        Assert.Equal(objects, token.ObjectCount);
    }

    [Theory]
    [InlineData(31)]
    [InlineData(56)]
    public void X25519_DestinationOfAnotherLength_IsRefused(int length)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenEcdhExportWorkspace(library);
        using var key = ImportMontgomeryKey(workspace, X25519Oid);

        Assert.Equal("destination", Assert.Throws<ArgumentException>(() =>
            key.DeriveAndExportSecret(RawEcdh([.. Enumerable.Repeat((byte)7, 32)]), new byte[length])).ParamName);
    }

    [Fact]
    public void X448_UsesItsOwnSize()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenEcdhExportWorkspace(library);
        using var key = ImportMontgomeryKey(workspace, X448Oid);
        byte[] u = [.. Enumerable.Range(1, 56).Select(i => (byte)i)];
        byte[] secret = new byte[56];

        key.DeriveAndExportSecret(RawEcdh(u), secret);

        Assert.Equal(StandIn(u), secret);
        Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(RawEcdh(u[..32]), new byte[32]));
    }

    // RFC 7748 §6.1: an all-zero shared secret is refused once read. Low-order peers are refused before the token
    // (above), so this is the backstop for a token that returns zeros anyway.
    [Fact]
    public void X25519_AllZeroSecret_IsRefused_ZeroedAndNotLoggedAsExported()
    {
        var logger = new CapturingLogger();
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token, new CapturingLoggerFactory(logger));
        using var workspace = OpenEcdhExportWorkspace(library);
        using var key = ImportMontgomeryKey(workspace, X25519Oid);
        int objects = token.ObjectCount;
        token.MontgomeryReturnsZeros = true;
        byte[] secret = [.. Enumerable.Repeat((byte)0xAA, 32)];

        Assert.Throws<CryptographicException>(() => key.DeriveAndExportSecret(RawEcdh([.. Enumerable.Repeat((byte)7, 32)]), secret));

        Assert.All(secret, b => Assert.Equal(0, b));
        Assert.Equal(objects, token.ObjectCount);
        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("allowed export", StringComparison.Ordinal));
    }

    // Low-order u-coordinates (RFC 7748 §7): the shared secret they give is fixed (all zeros) whatever the private
    // key, so any key derived from it, on the token or read back through a KDF, is known to an attacker.
    public static TheoryData<string> X25519LowOrder =>
    [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",   // bit 255 set: X25519 ignores it
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ];

    public static TheoryData<string> X448LowOrder =>
    [
        new string('0', 112),
        "01" + new string('0', 110),
        "fe" + new string('f', 54) + "fe" + new string('f', 54),
        new string('f', 56) + "fe" + new string('f', 54),
        new string('0', 56) + new string('f', 56),
    ];

    private static ObjectTemplate OnTokenAes() =>
        ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Encrypt().Decrypt().Build();

    [Theory]
    [MemberData(nameof(X25519LowOrder))]
    public void X25519_LowOrderPeer_IsRefused_OnTokenToo(string u)
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportMontgomeryKey(workspace, X25519Oid);
        int objects = token.ObjectCount;
        using var template = OnTokenAes();

        var ex = Assert.Throws<ArgumentException>(() => key.Derive(RawEcdh(Convert.FromHexString(u)), template));

        Assert.Equal("mechanism", ex.ParamName);
        Assert.Equal(objects, token.ObjectCount);
    }

    [Theory]
    [MemberData(nameof(X25519LowOrder))]
    public void X25519_LowOrderPeer_IsRefused_ForAReadBackThroughAKdf(string u)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportMontgomeryKey(workspace, X25519Oid);
        var mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, Convert.FromHexString(u)));

        Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(mechanism, new byte[32]));
    }

    [Theory]
    [MemberData(nameof(X448LowOrder))]
    public void X448_LowOrderPeer_IsRefused_OnTokenToo(string u)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportMontgomeryKey(workspace, X448Oid);
        using var template = OnTokenAes();

        Assert.Throws<ArgumentException>(() => key.Derive(RawEcdh(Convert.FromHexString(u)), template));
    }

    // PKCS#11 requires a token to accept the raw u-coordinate and only allows the DER-wrapped form, so the
    // library unwraps a wrapped peer before the token sees it.
    [Fact]
    public void X25519_WrappedPeer_ReachesTheTokenRaw()
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = OpenEcdhExportWorkspace(library);
        using var key = ImportMontgomeryKey(workspace, X25519Oid);
        byte[] u = [.. Enumerable.Range(100, 32).Select(i => (byte)i)];

        key.DeriveAndExportSecret(RawEcdh([0x04, 0x20, .. u]), new byte[32]);

        Assert.Equal(u, token.LastMontgomeryPeer);
    }

    [Fact]
    public void X25519_OnTokenDerivation_ChecksThePeerSize()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);
        using var key = ImportMontgomeryKey(workspace, X25519Oid);
        using var template = OnTokenAes();

        Assert.Throws<ArgumentException>(() => key.Derive(RawEcdh([.. Enumerable.Repeat((byte)7, 31)]), template));
    }

    [Fact]
    public void Montgomery_UnknownCurve_FailsClosed()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenEcdhExportWorkspace(library);
        using var key = ImportMontgomeryKey(workspace, [0x06, 0x03, 0x2B, 0x65, 0x70]);   // 1.3.101.112, Ed25519

        Assert.Throws<CryptographicException>(() =>
            key.DeriveAndExportSecret(RawEcdh([.. Enumerable.Repeat((byte)7, 32)]), new byte[32]));
    }

    // === EC helpers ===========================================================================

    [Fact]
    public void EcHelpers_RefuseANonEcKey()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var key = ImportHkdfKey(workspace);

        Assert.Throws<InvalidOperationException>(() => key.GetEcCurve());
        Assert.Throws<InvalidOperationException>(() => key.ExportEcPublicParameters());
    }

    [Fact(SkipUnless = nameof(EcSupported), Skip = "Requires " + nameof(EcSupported))]
    public void EcHelpers_ReportTheCurveAndPoint()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);

        Assert.Equal(Pkcs11ECCurve.NamedCurves.NistP256, key.GetEcCurve());
        Assert.Equal(256, key.GetEcCurve().FieldSizeBits);
        ECParameters parameters = key.ExportEcPublicParameters();
        Assert.Equal(32, parameters.Q.X!.Length);
        Assert.Null(parameters.D);
    }

    [Theory]
    [InlineData(32, new byte[] { 0x04, 0x41, 0x04 })]
    [InlineData(66, new byte[] { 0x04, 0x81, 0x85, 0x04 })]
    public void ForPeer_EncodesTheUncompressedPointAsADerOctetString(int coordinateLength, byte[] header)
    {
        byte[] x = [.. Enumerable.Repeat((byte)0xAA, coordinateLength)];
        byte[] y = [.. Enumerable.Repeat((byte)0xBB, coordinateLength)];

        var parameters = CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL, new ECParameters { Q = new ECPoint { X = x, Y = y } });

        byte[] encoded = parameters.PublicData.ToArray();
        Assert.Equal(header, encoded[..header.Length]);
        Assert.Equal([.. header, .. x, .. y], encoded);
    }

    [Fact]
    public void ForPeer_RefusesMissingOrUnequalCoordinates()
    {
        Assert.Throws<ArgumentException>(() => CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL, new ECParameters { Q = new ECPoint { X = new byte[32] } }));
        Assert.Throws<ArgumentException>(() => CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL,
            new ECParameters { Q = new ECPoint { X = new byte[32], Y = new byte[31] } }));
    }
}
