using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// These tests drive the gated legacy mechanisms/hashes on purpose (the AllowInsecure gate is the
// behaviour under test), so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11010

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SP800108HmacCounterKdfPkcs11 over the in-process <c>ManagedSoftToken</c>. SoftHSM ships the
/// <c>CKM_SP800_108_COUNTER_KDF</c> constants but has no operation path, so its known-answer
/// derivations skip; the managed token implements the mechanism by running the BCL
/// <see cref="SP800108HmacCounterKdf"/> over the data-param sequence the adapter emits, so every
/// derivation here is cross-checked byte-for-byte against that same BCL primitive.
/// Argument, key-type, PRF-validation and dispose cases throw before any token call and run
/// unconditionally; the derivations are gated on BCL KDF support.
/// </summary>
public sealed class SP800108HmacCounterKdfPkcs11_Managed
{
    public static bool Supported => true;

    private static readonly byte[] KeyBytes =
        Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    private static readonly byte[] Label = Encoding.UTF8.GetBytes("kdf-label");
    private static readonly byte[] Context = Encoding.UTF8.GetBytes("kdf-context");

    // Imports KeyBytes as a derive-capable generic-secret base key and hands the KDF to the body.
    private static void WithImportedKdf(HashAlgorithmName hash, Action<Pkcs11Workspace, SP800108HmacCounterKdfPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        // Every byte-returning DeriveKey overload reads the derived value off the token, so the gate
        // in BuildSecureKeyDefaults refuses them under the default posture. Opt in here; the refusal
        // itself is covered by its own test.
        workspace.AllowInsecure = true;
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("kdf").Value(KeyBytes).Derive().Build();
        using var key = workspace.ImportKey(tpl);
        using var kdf = new SP800108HmacCounterKdfPkcs11(key, hash);
        body(workspace, kdf);
    }

    private static void WithImportedKdf(Action<Pkcs11Workspace, SP800108HmacCounterKdfPkcs11> body) =>
        WithImportedKdf(HashAlgorithmName.SHA256, body);

    // Imports the base key and hands the raw Pkcs11Key (for ctor-validation tests).
    private static void WithImportedKdfKey(Action<Pkcs11Workspace, Pkcs11Key> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("kdf").Value(KeyBytes).Derive().Build();
        using var key = workspace.ImportKey(tpl);
        body(workspace, key);
    }

    // === Known-answer derivations: cross-checked against the BCL =========================

    [ConditionalTheory(nameof(Supported))]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void DeriveKey_MatchesBcl_AllPrfs(string hashName)
    {
        var alg = new HashAlgorithmName(hashName);
        WithImportedKdf(alg, (_, kdf) =>
        {
            const int length = 48; // spans multiple PRF blocks for every supported hash
            byte[] expected = SP800108HmacCounterKdf.DeriveBytes(KeyBytes, alg, Label, Context, length);

            byte[] actual = kdf.DeriveKey(Label, Context, length);

            Assert.Equal(expected, actual);
        });
    }

    [ConditionalFact(nameof(Supported))]
    public void DeriveKey_MatchesBcl() => WithImportedKdf((_, kdf) =>
    {
        const int length = 40; // spans two HMAC-SHA256 PRF blocks (32 bytes each)
        byte[] expected = SP800108HmacCounterKdf.DeriveBytes(
            KeyBytes, HashAlgorithmName.SHA256, Label, Context, length);

        byte[] actual = kdf.DeriveKey(Label, Context, length);

        Assert.Equal(expected, actual);
    });

    [ConditionalFact(nameof(Supported))]
    public void DeriveKey_DestinationSpan_MatchesBcl() => WithImportedKdf((_, kdf) =>
    {
        const int length = 32;
        byte[] expected = SP800108HmacCounterKdf.DeriveBytes(
            KeyBytes, HashAlgorithmName.SHA256, Label, Context, length);

        byte[] actual = new byte[length];
        kdf.DeriveKey(Label, Context, actual);

        Assert.Equal(expected, actual);
    });

    [ConditionalFact(nameof(Supported))]
    public void DeriveKey_IsDeterministic_SameInputsSameOutput() => WithImportedKdf((_, kdf) =>
    {
        byte[] first = kdf.DeriveKey(Label, Context, 64);
        byte[] second = kdf.DeriveKey(Label, Context, 64);
        Assert.Equal(first, second);
    });

    [ConditionalFact(nameof(Supported))]
    public void DeriveKey_DifferentLabel_ProducesDifferentOutput() => WithImportedKdf((_, kdf) =>
    {
        byte[] a = kdf.DeriveKey(Label, Context, 32);
        byte[] b = kdf.DeriveKey(Encoding.UTF8.GetBytes("other-label"), Context, 32);
        Assert.NotEqual(a, b);
    });

    [ConditionalFact(nameof(Supported))]
    public void DeriveKey_DifferentContext_ProducesDifferentOutput() => WithImportedKdf((_, kdf) =>
    {
        byte[] a = kdf.DeriveKey(Label, Context, 32);
        byte[] b = kdf.DeriveKey(Label, Encoding.UTF8.GetBytes("other-context"), 32);
        Assert.NotEqual(a, b);
    });

    // A SHA384 PRF must produce different keying material than SHA256 for identical label/context.
    [ConditionalFact(nameof(Supported))]
    public void DeriveKey_DifferentPrf_ProducesDifferentOutput()
    {
        byte[] sha256 = null!;
        WithImportedKdf(HashAlgorithmName.SHA256, (_, kdf) => sha256 = kdf.DeriveKey(Label, Context, 32));

        byte[] sha384 = null!;
        WithImportedKdf(HashAlgorithmName.SHA384, (_, kdf) => sha384 = kdf.DeriveKey(Label, Context, 32));

        Assert.NotEqual(sha256, sha384);
    }

    // The byte[] overload must agree with the destination-span overload for identical inputs.
    [ConditionalFact(nameof(Supported))]
    public void DeriveKey_ArrayAndSpanOverloads_Agree() => WithImportedKdf((_, kdf) =>
    {
        byte[] viaArray = kdf.DeriveKey(Label, Context, 32);
        byte[] viaSpan = new byte[32];
        kdf.DeriveKey((ReadOnlySpan<byte>)Label, Context, viaSpan);
        Assert.Equal(viaArray, viaSpan);
    });

    [ConditionalFact(nameof(Supported))]
    public void DeriveKey_EmptyLabelAndContext_MatchesBcl() => WithImportedKdf((_, kdf) =>
    {
        const int length = 32;
        // Typed empty span disambiguates DeriveBytes' byte[] vs ReadOnlySpan<byte> overloads.
        ReadOnlySpan<byte> empty = [];
        byte[] expected = SP800108HmacCounterKdf.DeriveBytes(
            KeyBytes, HashAlgorithmName.SHA256, empty, empty, length);

        byte[] actual = kdf.DeriveKey([], [], length);

        Assert.Equal(expected, actual);
    });

    // The on-token overload returns a Pkcs11Key handle; the managed token stores its CKA_VALUE, so we
    // can confirm the derived material matches the BCL. Non-extractability is enforced by a real HSM,
    // not by the in-process fake — that assertion lives in the SoftHsm/HSM test.
    [ConditionalFact(nameof(Supported))]
    public void DeriveKey_OnToken_DerivesBclMaterial() => WithImportedKdf((_, kdf) =>
    {
        const int length = 32;
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(length).Derive().Build();

        Pkcs11Key derived = kdf.DeriveKey(Label, Context, template);
        try
        {
            byte[] expected = SP800108HmacCounterKdf.DeriveBytes(
                KeyBytes, HashAlgorithmName.SHA256, Label, Context, length);
            var attrs = derived.GetAttributeValue(CKA.CKA_VALUE);
            Assert.NotEmpty(attrs);
            Assert.Equal(expected, attrs[0].GetValueAsByteArray());
        }
        finally
        {
            derived.Destroy();
            derived.Dispose();
        }
    });

    // === No-op / boundary behavior (matches the BCL) =====================================

    [ConditionalFact(nameof(Supported))]
    public void DeriveKey_ZeroLength_IsNoOp() => WithImportedKdf((_, kdf) =>
    {
        // Zero length is a no-op, matching the BCL SP800108HmacCounterKdf (no token call).
        Assert.Empty(kdf.DeriveKey(Label, Context, 0));
        kdf.DeriveKey(Label, Context, []); // must not throw
    });

    // === Argument and construction validation (run before the native call) ===============

    [Fact]
    public void Ctor_NullKey_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(
            () => new SP800108HmacCounterKdfPkcs11(null!, HashAlgorithmName.SHA256));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public void Ctor_NonGenericSecretKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        byte[] aes = new byte[32];
        RandomNumberGenerator.Fill(aes);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("kdf-aes").Value(aes).Derive().Build();
        using var key = workspace.ImportKey(tpl);

        var ex = Assert.Throws<ArgumentException>(
            () => new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.SHA256));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public void Ctor_UnsupportedPrfHash_Throws() => WithImportedKdfKey((_, key) =>
    {
        Assert.Throws<NotSupportedException>(
            () => new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.SHA1));
        Assert.Throws<NotSupportedException>(
            () => new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.MD5));
    });

    [Fact]
    public void DeriveKey_NegativeLength_Throws() => WithImportedKdf((_, kdf) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => kdf.DeriveKey(Label, Context, -1)));

    [Fact]
    public void DeriveKey_NullLabel_Throws() => WithImportedKdf((_, kdf) =>
    {
        var ex = Assert.Throws<ArgumentNullException>(() => kdf.DeriveKey(null!, Context, 16));
        Assert.Equal("label", ex.ParamName);
    });

    [Fact]
    public void DeriveKey_NullContext_Throws() => WithImportedKdf((_, kdf) =>
    {
        var ex = Assert.Throws<ArgumentNullException>(() => kdf.DeriveKey(Label, null!, 16));
        Assert.Equal("context", ex.ParamName);
    });

    [Fact]
    public void DeriveKey_OnToken_NullTemplate_Throws() => WithImportedKdf((_, kdf) =>
    {
        var ex = Assert.Throws<ArgumentNullException>(
            () => kdf.DeriveKey((ReadOnlySpan<byte>)Label, Context, (ObjectTemplate)null!));
        Assert.Equal("template", ex.ParamName);
    });

    [Fact]
    public void DeriveKey_AfterDispose_Throws() => WithImportedKdf((_, kdf) =>
    {
        kdf.Dispose();
        Assert.Throws<ObjectDisposedException>(() => kdf.DeriveKey(Label, Context, 16));
    });

    [Fact]
    public void Dispose_IsIdempotent() => WithImportedKdf((_, kdf) =>
    {
        kdf.Dispose();
        Assert.Null(Record.Exception(kdf.Dispose)); // second dispose must not throw
    });
}
