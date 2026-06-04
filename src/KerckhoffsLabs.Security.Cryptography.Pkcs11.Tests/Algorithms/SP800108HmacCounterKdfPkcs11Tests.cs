using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>Backend-free argument tests for <see cref="SP800108HmacCounterKdfPkcs11"/>.</summary>
public sealed class SP800108HmacCounterKdfPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(
            () => new SP800108HmacCounterKdfPkcs11(key: null!, HashAlgorithmName.SHA256));
}

/// <summary>
/// SP800108HmacCounterKdfPkcs11 over SoftHSM. Argument, key-type, PRF-validation and dispose tests
/// run unconditionally (they throw before any token call). The known-answer derivations require the
/// token to implement <c>CKM_SP800_108_COUNTER_KDF</c> — SoftHSM does not (the constants are in its
/// header but no operation path exists), so those skip here and run against a capable HSM.
/// </summary>
[Collection("SoftHsm")]
public sealed class SP800108HmacCounterKdfPkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    private static readonly byte[] KeyBytes =
        Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    private static readonly byte[] Label = Encoding.UTF8.GetBytes("kdf-label");
    private static readonly byte[] Context = Encoding.UTF8.GetBytes("kdf-context");

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    // Imports KeyBytes as a derive-capable generic-secret base key and hands the KDF to the body.
    private void WithImportedKdf(Action<Pkcs11Workspace, SP800108HmacCounterKdfPkcs11> body)
    {
        using var workspace = OpenWorkspace();
        string label = $"kdf-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(KeyBytes).Derive().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var kdf = new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.SHA256);
            body(workspace, kdf);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // SoftHSM does not implement SP800-108; skip the known-answer derivations when it is unavailable.
    private void RequireKdf()
    {
        if (!_backend.Supports(CKM.CKM_SP800_108_COUNTER_KDF))
            throw new SkipTestException(
                "Token does not implement CKM_SP800_108_COUNTER_KDF (SoftHSM ships the constants but no operation path).");
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonGenericSecretKey_Throws()
    {
        using var workspace = OpenWorkspace();
        string label = $"kdf-aes-{Guid.NewGuid():N}";
        byte[] aes = new byte[32];
        RandomNumberGenerator.Fill(aes);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(aes).Derive().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            var ex = Assert.Throws<ArgumentException>(
                () => new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.SHA256));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_UnsupportedPrfHash_Throws() => WithImportedKdfKey((_, key) =>
    {
        Assert.Throws<NotSupportedException>(
            () => new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.SHA1));
        Assert.Throws<NotSupportedException>(
            () => new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.MD5));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void DeriveKey_NegativeLength_Throws() => WithImportedKdf((_, kdf) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => kdf.DeriveKey(Label, Context, -1)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void DeriveKey_ZeroLength_IsNoOp() => WithImportedKdf((_, kdf) =>
    {
        // Zero length is a no-op, matching the BCL SP800108HmacCounterKdf (no token call).
        Assert.Empty(kdf.DeriveKey(Label, Context, 0));
        kdf.DeriveKey(Label, Context, Span<byte>.Empty); // must not throw
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void DeriveKey_AfterDispose_Throws() => WithImportedKdf((_, kdf) =>
    {
        kdf.Dispose();
        Assert.Throws<ObjectDisposedException>(() => kdf.DeriveKey(Label, Context, 16));
    });

    // === Known-answer derivations (require token SP800-108 support; skip on SoftHSM) ================

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void DeriveKey_MatchesBcl() => WithImportedKdf((_, kdf) =>
    {
        RequireKdf();
        const int length = 40; // spans two HMAC-SHA256 PRF blocks (32 bytes each)
        byte[] expected = SP800108HmacCounterKdf.DeriveBytes(
            KeyBytes, HashAlgorithmName.SHA256, Label, Context, length);

        byte[] actual = kdf.DeriveKey(Label, Context, length);

        Assert.Equal(expected, actual);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void DeriveKey_DestinationSpan_MatchesBcl() => WithImportedKdf((_, kdf) =>
    {
        RequireKdf();
        const int length = 32;
        byte[] expected = SP800108HmacCounterKdf.DeriveBytes(
            KeyBytes, HashAlgorithmName.SHA256, Label, Context, length);

        byte[] actual = new byte[length];
        kdf.DeriveKey(Label, Context, actual);

        Assert.Equal(expected, actual);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void DeriveKey_OnToken_ReturnsNonExtractableKey() => WithImportedKdf((_, kdf) =>
    {
        RequireKdf();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(32).Derive().NonExtractable().Sensitive().Build();

        Pkcs11Key derived = kdf.DeriveKey(Label, Context, template);
        try
        {
            // The derived sub-key stays on the token: its value must not be readable.
            var attrs = derived.GetAttributeValue(CKA.CKA_VALUE);
            Assert.True(attrs.Count == 0 || attrs[0].CannotBeRead);
        }
        finally
        {
            derived.Delete();
            derived.Dispose();
        }
    });

    // Imports the base key and hands the raw Pkcs11Key (for ctor-validation tests).
    private void WithImportedKdfKey(Action<Pkcs11Workspace, Pkcs11Key> body)
    {
        using var workspace = OpenWorkspace();
        string label = $"kdf-raw-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(KeyBytes).Derive().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            body(workspace, key);
        }
        finally { DestroyByLabel(workspace, label); }
    }
}
