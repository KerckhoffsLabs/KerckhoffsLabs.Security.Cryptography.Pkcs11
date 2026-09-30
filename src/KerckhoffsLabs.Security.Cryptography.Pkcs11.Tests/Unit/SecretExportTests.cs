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
            CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, Reason));
        using var key = ImportHkdfKey(workspace);
        int objectsBefore = token.ObjectCount;

        byte[] output = new byte[42];
        key.DeriveAndExportSecret(Hkdf(), output);

        Assert.Equal(ExpectedHkdf(42), output);
        Assert.Equal(objectsBefore, token.ObjectCount);
    }

    [Fact]
    public void Hkdf_UnderSecureOnly_IsRefusedAsAnExport_NamingTheMechanismAndBaseKey()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var key = ImportHkdfKey(workspace);
        byte[] output = new byte[32];

        var ex = Assert.Throws<CryptoPolicyViolationException>(() => key.DeriveAndExportSecret(Hkdf(), output));

        var request = Assert.IsType<KeyMaterialExportRequest>(ex.Request);
        Assert.Equal(KeyMaterialExportKind.KdfOutput, request.Kind);
        Assert.Equal(CKM.CKM_HKDF_DERIVE, request.Mechanism);
        Assert.Equal(CKO.CKO_SECRET_KEY, request.BaseKeyClass);
        Assert.Equal(CKK.CKK_GENERIC_SECRET, request.BaseKeyType);
        Assert.Contains("WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, reason)", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EphemeralTemplate_StatesEveryRestriction_ButNotCkaModifiable()
    {
        List<ObjectAttribute> template = SecretExport.EphemeralTemplate(32);
        try
        {
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
        finally
        {
            SecretExport.Release(template);
        }
    }

    [Fact]
    public void AllowedExport_DoesNotSubmitTheEphemeralTemplate_ButStillJudgesTheMechanism()
    {
        var policy = new RecordingPolicy(CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, Reason));
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, policy);
        using var key = ImportHkdfKey(workspace);
        policy.Seen.Clear();

        key.DeriveAndExportSecret(Hkdf(), new byte[32]);

        Assert.Single(policy.Seen.OfType<KeyMaterialExportRequest>());
        Assert.Contains(policy.Seen, r => r is MechanismUseRequest { Operation: CryptoOperation.Derive });
        Assert.Empty(policy.Seen.OfType<KeyTemplateRequest>());
    }

    [Fact]
    public void TheWaiver_EndsWithTheCall()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, Reason));
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
            CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, Reason));
        using var key = ImportHkdfKey(workspace);

        key.DeriveAndExportSecret(Hkdf(), new byte[32]);

        var entry = Assert.Single(logger.Entries, e => e.Message.Contains("allowed export", StringComparison.Ordinal));
        Assert.Equal(Microsoft.Extensions.Logging.LogLevel.Information, entry.Level);
        Assert.Contains("KdfOutput", entry.Message, StringComparison.Ordinal);
        Assert.Contains("CKM_HKDF_DERIVE", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FailedDestroy_ZeroesTheDestination_AndSurfacesTheTokensCode()
    {
        var token = new ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, Reason));
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
    }

    [Fact]
    public void Sp800108Counter_MatchesTheBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, Reason));
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

        var ex = Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(Hkdf(), Span<byte>.Empty));

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
            CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.PasswordKdfOutput, Reason));
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
            CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KdfOutput, Reason));
        using var password = new SecurePassword("placeholder-password"u8);

        var ex = Assert.Throws<CryptoPolicyViolationException>(() => workspace.DeriveAndExportSecret(Pbkdf2(password), new byte[32]));

        var request = Assert.IsType<KeyMaterialExportRequest>(ex.Request);
        Assert.Equal(KeyMaterialExportKind.PasswordKdfOutput, request.Kind);
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
            CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.EcdhSharedSecret, Reason));
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
            CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.EcdhSharedSecret, Reason));
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        var offCurve = new ECParameters
        {
            Curve = BclECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = new byte[32], Y = [.. Enumerable.Repeat((byte)1, 32)] },
        };

        var ex = Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(
            new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL, offCurve)), new byte[32]));

        Assert.Equal("mechanism", ex.ParamName);
    }

    [Fact(SkipUnless = nameof(EcSupported), Skip = "Requires " + nameof(EcSupported))]
    public void Ecdh_PeerPointOfAnotherSize_IsRefused()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.EcdhSharedSecret, Reason));
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var p384 = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP384);

        Assert.Throws<ArgumentException>(() => key.DeriveAndExportSecret(
            new Mechanism(CKM.CKM_ECDH1_DERIVE, CkmEcdh1DeriveParams.ForPeer(CKD.CKD_NULL, p384.ExportParameters(false))), new byte[32]));
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

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Kem_RoundTrips_UnderItsOptIn()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library,
            CryptoPolicy.SecureOnly.WithAllowedKeyMaterialExport(KeyMaterialExportKind.KemSharedSecret, Reason));
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
