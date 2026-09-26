using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

// This test drives a gated legacy mechanism on purpose (IsPermitted's false-verdict path is the
// behaviour under test), so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

public sealed class Pkcs11SessionPolicyTests
{
    private sealed class RecordingPolicy(Func<PolicyRequest, PolicyDecision> verdict) : ICryptoPolicy
    {
        public List<PolicyRequest> Seen { get; } = [];
        public string Name => "Recording";
        public bool AllowsOverride => true;
        public PolicyDecision Evaluate(PolicyRequest request)
        {
            Seen.Add(request);
            return verdict(request);
        }
    }

    private sealed class CountingFake : FakeLowLevelPkcs11Library
    {
        public int EncryptInits { get; private set; }
        public override CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
        {
            EncryptInits++;
            return base.C_EncryptInit(session, ref mechanism, key);
        }
    }

    private static readonly ObjectHandle AnyKey = new(0);

    [Fact]
    public void DefaultPolicy_IsSecureOnly()
    {
        using var session = new Pkcs11Session(new FakeLowLevelPkcs11Library(), 1);
        Assert.Same(CryptoPolicy.SecureOnly, session.Policy);
    }

    [Fact]
    public void CustomPolicy_IsConsulted_WithTheOperation()
    {
        var policy = new RecordingPolicy(_ => PolicyDecision.Allow);
        using var session = new Pkcs11Session(new FakeLowLevelPkcs11Library(), 1, policy: policy);

        _ = Record.Exception(() => session.Encrypt(new Mechanism(CKM.CKM_AES_GCM), AnyKey, [1]));

        var use = Assert.IsType<MechanismUseRequest>(Assert.Single(policy.Seen));
        Assert.Equal(CryptoOperation.Encrypt, use.Operation);
        Assert.Equal((ulong)CKM.CKM_AES_GCM, use.Mechanism.Type);
    }

    [Fact]
    public void Denial_ThrowsWithPolicyDetails_AndNeverReachesTheToken()
    {
        var fake = new CountingFake();
        var policy = new RecordingPolicy(_ => PolicyDecision.Deny("nope"));
        using var session = new Pkcs11Session(fake, 1, policy: policy);

        var ex = Assert.Throws<CryptoPolicyViolationException>(
            () => session.Encrypt(new Mechanism(CKM.CKM_AES_GCM), AnyKey, [1]));

        Assert.Equal("Recording", ex.PolicyName);
        Assert.Equal("nope", ex.Reason);
        Assert.Equal(CKM.CKM_AES_GCM, ex.Mechanism);
        Assert.Equal(0, fake.EncryptInits);
    }

    [Fact]
    public void PolicyReturningDefault_IsADenial()
    {
        using var session = new Pkcs11Session(new FakeLowLevelPkcs11Library(), 1, policy: new RecordingPolicy(_ => default));

        var ex = Assert.Throws<CryptoPolicyViolationException>(
            () => session.Encrypt(new Mechanism(CKM.CKM_AES_GCM), AnyKey, [1]));

        Assert.Equal("The policy returned no decision.", ex.Reason);
    }

    [Fact]
    public void PolicyThatThrows_AbortsWithItsOwnException()
    {
        var fake = new CountingFake();
        using var session = new Pkcs11Session(fake, 1,
            policy: new RecordingPolicy(_ => throw new InvalidOperationException("policy bug")));

        var ex = Assert.Throws<InvalidOperationException>(
            () => session.Encrypt(new Mechanism(CKM.CKM_AES_GCM), AnyKey, [1]));

        Assert.Equal("policy bug", ex.Message);
        Assert.Equal(0, fake.EncryptInits);
    }

    [Fact]
    public void IsPermitted_ReturnsTheVerdict_WithoutThrowing()
    {
        using var session = new Pkcs11Session(new FakeLowLevelPkcs11Library(), 1);
        Assert.False(session.IsPermitted(new MechanismUseRequest(new Mechanism(CKM.CKM_DES_ECB), CryptoOperation.Encrypt)));
        Assert.True(session.IsPermitted(new MechanismUseRequest(new Mechanism(CKM.CKM_AES_GCM), CryptoOperation.Encrypt)));
    }

    [Fact]
    public void KeyTemplateRequest_CarriesTheKnownObjectClass()
    {
        var policy = new RecordingPolicy(_ => PolicyDecision.Allow);
        using var session = new Pkcs11Session(new FakeLowLevelPkcs11Library(), 1, policy: policy);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();

        _ = Record.Exception(() => session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), [.. tpl.Attributes]));

        var template = Assert.Single(policy.Seen.OfType<KeyTemplateRequest>());
        Assert.Equal(CKO.CKO_SECRET_KEY, template.ObjectClass);
    }

    [Fact]
    public void DenialLog_NamesPolicyAndRequest_ButNoAttributeValues()
    {
        var logger = new CapturingLogger();
        using var session = new Pkcs11Session(new FakeLowLevelPkcs11Library(), 1, new CapturingLoggerFactory(logger));
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label("do-not-log-me").ValueLen(32).Sensitive(false).Build();

        Assert.Throws<CryptoPolicyViolationException>(
            () => session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), [.. tpl.Attributes]));

        var entry = Assert.Single(logger.Entries, e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning);
        Assert.Contains("SecureOnly", entry.Message, StringComparison.Ordinal);
        Assert.Contains("key template", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("do-not-log-me", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void WorkspacePassThrough_EnforcesTheSessionPolicy()
    {
        using var library = Support.Pkcs11Fakes.ManagedToken.NewLibrary();
        using var workspace = Support.Pkcs11Fakes.ManagedToken.OpenWorkspace(library);
        var request = new KeyMaterialExportRequest(KeyMaterialExportKind.KemSharedSecret);

        var ex = Assert.Throws<CryptoPolicyViolationException>(() => workspace.Enforce(request));

        Assert.Equal("SecureOnly", ex.PolicyName);
        Assert.Same(request, ex.Request);
        Assert.False(workspace.IsPermitted(request));
    }

    [Fact]
    public void FipsOnly_AesCbcEmptyInput_ShortCircuits_WithoutTouchingTheToken()
    {
        var token = new Support.Pkcs11Fakes.ManagedSoftToken();
        using var library = new Pkcs11Library(token);
        using var workspace = Support.Pkcs11Fakes.ManagedToken.OpenWorkspace(library, CryptoPolicy.FipsOnly);
        using var key = workspace.GenerateAesKey(256);
        using var aes = new AesPkcs11(key);

        byte[] output = aes.EncryptCbc(Array.Empty<byte>(), new byte[16], System.Security.Cryptography.PaddingMode.None);

        Assert.Empty(output);
        Assert.Equal(0, token.EncryptInitCallCount);
    }

    [Fact]
    public void IsPermitted_OnADisposedSession_Throws()
    {
        var session = new Pkcs11Session(new FakeLowLevelPkcs11Library(), 1);
        session.Dispose();

        Assert.Throws<ObjectDisposedException>(() => session.IsPermitted(
            new MechanismUseRequest(new Mechanism(CKM.CKM_AES_GCM), CryptoOperation.Encrypt)));
    }

    [Fact]
    public void IsPermitted_OnADisposedWorkspace_Throws()
    {
        using var library = Support.Pkcs11Fakes.ManagedToken.NewLibrary();
        var workspace = Support.Pkcs11Fakes.ManagedToken.OpenWorkspace(library);
        workspace.Dispose();

        Assert.Throws<ObjectDisposedException>(() => workspace.IsPermitted(
            new KeyMaterialExportRequest(KeyMaterialExportKind.KdfOutput)));
    }

    [Fact]
    public void UsePolicy_LogsAWarningOnEntry_NamingBothPolicies()
    {
        var logger = new CapturingLogger();
        using var session = new Pkcs11Session(new FakeLowLevelPkcs11Library(), 1, new CapturingLoggerFactory(logger), CryptoPolicy.SecureOnly);

        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
            var entry = Assert.Single(logger.Entries, e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning);
            Assert.Contains("SecureOnly", entry.Message, StringComparison.Ordinal);
            Assert.Contains("AllowInsecure", entry.Message, StringComparison.Ordinal);
            Assert.True(entry.Message.IndexOf("SecureOnly", StringComparison.Ordinal)
                < entry.Message.IndexOf("AllowInsecure", StringComparison.Ordinal), "from-policy precedes to-policy");
        }
    }

    [Fact]
    public void DisposingAnOverrideLease_LogsTheRestore()
    {
        var logger = new CapturingLogger();
        using var session = new Pkcs11Session(new FakeLowLevelPkcs11Library(), 1, new CapturingLoggerFactory(logger), CryptoPolicy.SecureOnly);

        session.UsePolicy(CryptoPolicy.AllowInsecure).Dispose();

        var restore = Assert.Single(logger.Entries, e => e.Message.Contains("restored", StringComparison.Ordinal));
        Assert.Equal(Microsoft.Extensions.Logging.LogLevel.Information, restore.Level);
        Assert.Contains("AllowInsecure -> SecureOnly", restore.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Pbkdf2_ReadingTheDerivedBytes_RaisesTheKdfOutputExportCheck()
    {
        var policy = new RecordingPolicy(r => r is KeyMaterialExportRequest
            ? PolicyDecision.Deny("no export")
            : CryptoPolicy.AllowInsecure.Evaluate(r));
        using var library = Support.Pkcs11Fakes.ManagedToken.NewLibrary();
        using var workspace = Support.Pkcs11Fakes.ManagedToken.OpenWorkspace(library, policy);

        var ex = Assert.Throws<CryptoPolicyViolationException>(() => Rfc2898DeriveBytesPkcs11.Pbkdf2(
            workspace, "placeholder-password"u8.ToArray(), new byte[16], 1000, System.Security.Cryptography.HashAlgorithmName.SHA256, 32));

        var export = Assert.IsType<KeyMaterialExportRequest>(ex.Request);
        Assert.Equal(KeyMaterialExportKind.KdfOutput, export.Kind);
        Assert.Equal("no export", ex.Reason);
        Assert.Empty(policy.Seen.OfType<KeyTemplateRequest>()); // refused before any key template was built or sent
    }

    [Fact]
    public void Pbkdf2_UnderAllowInsecure_PassesThePolicy_AndReachesTheToken()
    {
        using var library = Support.Pkcs11Fakes.ManagedToken.NewLibrary();
        using var workspace = Support.Pkcs11Fakes.ManagedToken.OpenWorkspace(library, CryptoPolicy.AllowInsecure);

        // The managed soft token does not implement CKM_PKCS5_PBKD2, so a token error (not a policy
        // refusal) is the proof that every policy check passed and the call reached C_GenerateKey.
        var ex = Record.Exception(() => Rfc2898DeriveBytesPkcs11.Pbkdf2(
            workspace, "placeholder-password"u8.ToArray(), new byte[16], 1000, System.Security.Cryptography.HashAlgorithmName.SHA256, 32));

        var tokenError = Assert.IsAssignableFrom<Pkcs11Exception>(ex);
        Assert.Equal(CKR.CKR_MECHANISM_INVALID, tokenError.ReturnValue);
    }
}
