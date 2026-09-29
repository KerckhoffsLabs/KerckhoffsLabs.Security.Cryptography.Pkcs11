using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// SHA-1 and MD5 are passed on purpose: their refusal is the behaviour under test.
#pragma warning disable KLPKCS11010

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// <see cref="HkdfPkcs11"/> over the in-process <c>ManagedSoftToken</c>, which runs
/// <c>CKM_HKDF_DERIVE</c> through the BCL <see cref="HKDF"/>. Every byte result is compared with
/// <see cref="HKDF"/> for the same inputs, and every argument error with the exception <see cref="HKDF"/>
/// throws for the same bad argument, so the adapter's contract is checked against the BCL's own.
/// </summary>
[NoBackendCollection("Drives a per-test ManagedSoftToken in process — no native module is loaded and " +
                     "the token holds no static state, so this is safe alongside every backend collection.")]
public sealed class HkdfPkcs11Tests_Managed
{
    // RFC 5869 appendix A.1 (SHA-256).
    private static readonly byte[] Ikm = Convert.FromHexString("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
    private static readonly byte[] Salt = Convert.FromHexString("000102030405060708090A0B0C");
    private static readonly byte[] Info = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9");
    private static readonly byte[] Rfc5869Okm = Convert.FromHexString(
        "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865");

    private static readonly HashAlgorithmName Sha256 = HashAlgorithmName.SHA256;

    public static TheoryData<string> Hashes()
    {
        var data = new TheoryData<string> { "SHA256", "SHA384", "SHA512" };
        if (SHA3_256.IsSupported)
        {
            data.Add("SHA3-256");
            data.Add("SHA3-384");
            data.Add("SHA3-512");
        }
        return data;
    }

    // Imports Ikm as a derive-capable generic-secret key. The byte-returning overloads read the derived
    // value off the token, so they need the export opt-in; the on-token overloads must work without it.
    private static void WithIkm(bool allowExport, Action<Pkcs11Workspace, Pkcs11Key> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).Label("ikm").Value(Ikm).Derive().Build();
        using var ikm = workspace.ImportKey(tpl);
        if (!allowExport)
        {
            body(workspace, ikm);
            return;
        }
        using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
        body(workspace, ikm);
    }

    private static void WithIkm(Action<Pkcs11Workspace, Pkcs11Key> body) => WithIkm(allowExport: true, body);

    private static byte[] ValueOf(Pkcs11Key key)
    {
        using var attrs = key.GetAttributeValue(CKA.CKA_VALUE);
        return attrs[0].GetValueAsByteArray();
    }

    private static ObjectTemplate SecretTemplate(int length) =>
        ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(length).Derive().Build();

    // === Known answers =====================================================================

    [Fact]
    public void DeriveKey_MatchesRfc5869TestVector() => WithIkm((_, ikm) =>
        Assert.Equal(Rfc5869Okm, HkdfPkcs11.DeriveKey(Sha256, ikm, 42, Salt, Info)));

    [Theory]
    [MemberData(nameof(Hashes))]
    public void DeriveKey_MatchesBcl(string hash) => WithIkm((_, ikm) =>
    {
        var h = new HashAlgorithmName(hash);
        Assert.Equal(HKDF.DeriveKey(h, Ikm, 100, Salt, Info), HkdfPkcs11.DeriveKey(h, ikm, 100, Salt, Info));
    });

    [Fact]
    public void DeriveKey_Span_MatchesBcl() => WithIkm((_, ikm) =>
    {
        byte[] expected = new byte[40];
        HKDF.DeriveKey(Sha256, Ikm, expected, Salt, Info);
        byte[] actual = new byte[40];
        HkdfPkcs11.DeriveKey(Sha256, ikm, actual, Salt, Info);
        Assert.Equal(expected, actual);
    });

    // A null, an empty and an all-zero salt of hash length are the same salt in RFC 5869.
    [Fact]
    public void DeriveKey_NullEmptyAndZeroSalt_MatchBcl() => WithIkm((_, ikm) =>
    {
        byte[] expected = HKDF.DeriveKey(Sha256, Ikm, 32);
        Assert.Equal(expected, HkdfPkcs11.DeriveKey(Sha256, ikm, 32));
        Assert.Equal(expected, HkdfPkcs11.DeriveKey(Sha256, ikm, 32, salt: [], info: []));
        Assert.Equal(expected, HkdfPkcs11.DeriveKey(Sha256, ikm, 32, salt: new byte[32]));
    });

    [Theory]
    [MemberData(nameof(Hashes))]
    public void Extract_MatchesBcl(string hash) => WithIkm((_, ikm) =>
    {
        var h = new HashAlgorithmName(hash);
        Assert.Equal(HKDF.Extract(h, Ikm, Salt), HkdfPkcs11.Extract(h, ikm, Salt));
    });

    [Fact]
    public void Extract_Span_WritesOneHashLength_AndMatchesBcl() => WithIkm((_, ikm) =>
    {
        byte[] expected = new byte[40];
        int expectedWritten = HKDF.Extract(Sha256, Ikm, Salt, expected);
        byte[] actual = new byte[40];
        int written = HkdfPkcs11.Extract(Sha256, ikm, Salt, actual);
        Assert.Equal(expectedWritten, written);
        Assert.Equal(expected, actual);
    });

    [Theory]
    [MemberData(nameof(Hashes))]
    public void ExtractKey_ThenExpand_MatchesBclDeriveKey(string hash) => WithIkm((_, ikm) =>
    {
        var h = new HashAlgorithmName(hash);
        using Pkcs11Key prk = HkdfPkcs11.ExtractKey(h, ikm, Salt);
        Assert.Equal(HKDF.DeriveKey(h, Ikm, 80, Salt, Info), HkdfPkcs11.Expand(h, prk, 80, Info));
    });

    [Fact]
    public void Expand_Span_MatchesBcl() => WithIkm((_, ikm) =>
    {
        byte[] prkBytes = HKDF.Extract(Sha256, Ikm, Salt);
        byte[] expected = new byte[50];
        HKDF.Expand(Sha256, prkBytes, expected, Info);

        using Pkcs11Key prk = HkdfPkcs11.ExtractKey(Sha256, ikm, Salt);
        byte[] actual = new byte[50];
        HkdfPkcs11.Expand(Sha256, prk, actual, Info);
        Assert.Equal(expected, actual);
    });

    // === On-token additions: work under the default policy =================================

    [Fact]
    public void DeriveKey_OnToken_WorksUnderTheDefaultPolicy_AndMatchesBcl() => WithIkm(allowExport: false, (_, ikm) =>
    {
        using var template = SecretTemplate(32);
        using Pkcs11Key derived = HkdfPkcs11.DeriveKey(Sha256, ikm, template, Salt, Info);
        // The managed token does not enforce sensitivity, so the value can be compared here; a real
        // token's non-extractability is covered by the backend tests.
        Assert.Equal(HKDF.DeriveKey(Sha256, Ikm, 32, Salt, Info), ValueOf(derived));
    });

    [Fact]
    public void ExtractKey_ThenExpandKey_WorkUnderTheDefaultPolicy_AndMatchBcl() => WithIkm(allowExport: false, (_, ikm) =>
    {
        using Pkcs11Key prk = HkdfPkcs11.ExtractKey(Sha256, ikm, Salt);
        using var template = SecretTemplate(48);
        using Pkcs11Key okm = HkdfPkcs11.ExpandKey(Sha256, prk, template, Info);
        Assert.Equal(HKDF.DeriveKey(Sha256, Ikm, 48, Salt, Info), ValueOf(okm));
    });

    [Fact]
    public void ExtractKey_ReturnsASensitiveNonExtractableSessionDeriveKey() => WithIkm(allowExport: false, (_, ikm) =>
    {
        using Pkcs11Key prk = HkdfPkcs11.ExtractKey(Sha256, ikm, Salt);
        using var attrs = prk.GetAttributeValue(CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE, CKA.CKA_TOKEN, CKA.CKA_DERIVE, CKA.CKA_VALUE_LEN);
        Assert.True(attrs[0].GetValueAsBool());
        Assert.False(attrs[1].GetValueAsBool());
        Assert.False(attrs[2].GetValueAsBool());
        Assert.True(attrs[3].GetValueAsBool());
        Assert.Equal(32UL, attrs[4].GetValueAsUlong());
    });

    // === Byte results read key material off the token: refused by default ====================

    [Fact]
    public void ByteResults_AreRefusedUnderTheDefaultPolicy() => WithIkm(allowExport: false, (_, ikm) =>
    {
        using Pkcs11Key prk = HkdfPkcs11.ExtractKey(Sha256, ikm, Salt);
        Assert.Throws<CryptoPolicyViolationException>(() => HkdfPkcs11.DeriveKey(Sha256, ikm, 32, Salt, Info));
        Assert.Throws<CryptoPolicyViolationException>(() => HkdfPkcs11.DeriveKey(Sha256, ikm, new byte[32], Salt, Info));
        Assert.Throws<CryptoPolicyViolationException>(() => HkdfPkcs11.Extract(Sha256, ikm, Salt));
        Assert.Throws<CryptoPolicyViolationException>(() => HkdfPkcs11.Extract(Sha256, ikm, Salt, new byte[32]));
        Assert.Throws<CryptoPolicyViolationException>(() => HkdfPkcs11.Expand(Sha256, prk, 32, Info));
        Assert.Throws<CryptoPolicyViolationException>(() => HkdfPkcs11.Expand(Sha256, prk, new byte[32], Info));
    });

    // === Argument errors: the same exception HKDF throws for the same bad argument ==========

    private static void AssertSameFailureAsBcl(Action bcl, Action adapter)
    {
        Exception expected = Assert.ThrowsAny<Exception>(bcl);
        Exception actual = Assert.ThrowsAny<Exception>(adapter);
        Assert.Equal(expected.GetType(), actual.GetType());
        Assert.Equal((expected as ArgumentException)?.ParamName, (actual as ArgumentException)?.ParamName);
    }

    private static readonly HashAlgorithmName Unknown = new("NOT-A-HASH");

    [Fact]
    public void DeriveKey_ArgumentErrors_MatchBcl() => WithIkm((_, ikm) =>
    {
        AssertSameFailureAsBcl(() => HKDF.DeriveKey(Sha256, null!, 16), () => HkdfPkcs11.DeriveKey(Sha256, null!, 16));
        AssertSameFailureAsBcl(() => HKDF.DeriveKey(Sha256, Ikm, 0), () => HkdfPkcs11.DeriveKey(Sha256, ikm, 0));
        AssertSameFailureAsBcl(() => HKDF.DeriveKey(Sha256, Ikm, -1), () => HkdfPkcs11.DeriveKey(Sha256, ikm, -1));
        AssertSameFailureAsBcl(() => HKDF.DeriveKey(Sha256, Ikm, 255 * 32 + 1), () => HkdfPkcs11.DeriveKey(Sha256, ikm, 255 * 32 + 1));
        AssertSameFailureAsBcl(() => HKDF.DeriveKey(Unknown, Ikm, 16), () => HkdfPkcs11.DeriveKey(Unknown, ikm, 16));
        AssertSameFailureAsBcl(() => HKDF.DeriveKey(default, Ikm, 16), () => HkdfPkcs11.DeriveKey(default, ikm, 16));
        // Validation order: a bad length is reported before a bad hash, as HKDF does.
        AssertSameFailureAsBcl(() => HKDF.DeriveKey(Unknown, Ikm, 0), () => HkdfPkcs11.DeriveKey(Unknown, ikm, 0));
    });

    [Fact]
    public void DeriveKey_Span_ArgumentErrors_MatchBcl() => WithIkm((_, ikm) =>
    {
        AssertSameFailureAsBcl(() => HKDF.DeriveKey(Sha256, Ikm, [], Salt, Info), () => HkdfPkcs11.DeriveKey(Sha256, ikm, [], Salt, Info));
        AssertSameFailureAsBcl(() => HKDF.DeriveKey(Sha256, Ikm, new byte[255 * 32 + 1], Salt, Info),
            () => HkdfPkcs11.DeriveKey(Sha256, ikm, new byte[255 * 32 + 1], Salt, Info));
        AssertSameFailureAsBcl(() => HKDF.DeriveKey(Unknown, Ikm, new byte[16], Salt, Info), () => HkdfPkcs11.DeriveKey(Unknown, ikm, new byte[16], Salt, Info));
        // Validation order: a bad hash is reported before an empty output, as HKDF does.
        AssertSameFailureAsBcl(() => HKDF.DeriveKey(Unknown, Ikm, [], Salt, Info), () => HkdfPkcs11.DeriveKey(Unknown, ikm, [], Salt, Info));
    });

    [Fact]
    public void Extract_ArgumentErrors_MatchBcl() => WithIkm((_, ikm) =>
    {
        AssertSameFailureAsBcl(() => HKDF.Extract(Sha256, null!), () => HkdfPkcs11.Extract(Sha256, null!));
        AssertSameFailureAsBcl(() => HKDF.Extract(Unknown, Ikm), () => HkdfPkcs11.Extract(Unknown, ikm));
        AssertSameFailureAsBcl(() => HKDF.Extract(Sha256, Ikm, Salt, new byte[31]), () => HkdfPkcs11.Extract(Sha256, ikm, Salt, new byte[31]));
        AssertSameFailureAsBcl(() => HKDF.Extract(Unknown, Ikm, Salt, new byte[1]), () => HkdfPkcs11.Extract(Unknown, ikm, Salt, new byte[1]));
    });

    [Fact]
    public void Expand_ArgumentErrors_MatchBcl() => WithIkm((_, ikm) =>
    {
        byte[] prkBytes = HKDF.Extract(Sha256, Ikm, Salt);
        using Pkcs11Key prk = HkdfPkcs11.ExtractKey(Sha256, ikm, Salt);

        AssertSameFailureAsBcl(() => HKDF.Expand(Sha256, null!, 16), () => HkdfPkcs11.Expand(Sha256, null!, 16));
        AssertSameFailureAsBcl(() => HKDF.Expand(Sha256, prkBytes, 0), () => HkdfPkcs11.Expand(Sha256, prk, 0));
        AssertSameFailureAsBcl(() => HKDF.Expand(Sha256, prkBytes, 255 * 32 + 1), () => HkdfPkcs11.Expand(Sha256, prk, 255 * 32 + 1));
        AssertSameFailureAsBcl(() => HKDF.Expand(Unknown, prkBytes, 16), () => HkdfPkcs11.Expand(Unknown, prk, 16));
        AssertSameFailureAsBcl(() => HKDF.Expand(Sha256, prkBytes, [], Info), () => HkdfPkcs11.Expand(Sha256, prk, [], Info));
        AssertSameFailureAsBcl(() => HKDF.Expand(Sha256, prkBytes, new byte[255 * 32 + 1], Info),
            () => HkdfPkcs11.Expand(Sha256, prk, new byte[255 * 32 + 1], Info));
        AssertSameFailureAsBcl(() => HKDF.Expand(Unknown, prkBytes, [], Info), () => HkdfPkcs11.Expand(Unknown, prk, [], Info));
    });

    // HKDF refuses a PRK shorter than the hash length; the adapter does too when the token reports the
    // key's length.
    [Fact]
    public void Expand_ShortPrk_MatchesBcl() => WithIkm((_, ikm) =>
    {
        byte[] shortPrkBytes = new byte[16];
        using var shortTemplate = SecretTemplate(16);
        using Pkcs11Key shortPrk = HkdfPkcs11.DeriveKey(Sha256, ikm, shortTemplate, Salt, Info);
        using var template = SecretTemplate(32);

        AssertSameFailureAsBcl(() => HKDF.Expand(Sha256, shortPrkBytes, 32), () => HkdfPkcs11.Expand(Sha256, shortPrk, 32));
        AssertSameFailureAsBcl(() => HKDF.Expand(Sha256, shortPrkBytes, new byte[32], Info), () => HkdfPkcs11.Expand(Sha256, shortPrk, new byte[32], Info));
        var ex = Assert.Throws<ArgumentException>(() => HkdfPkcs11.ExpandKey(Sha256, shortPrk, template, Info));
        Assert.Equal("prk", ex.ParamName);
    });

    // === Deliberate deviations and additions ================================================

    [Theory]
    [InlineData("SHA1")]
    [InlineData("MD5")]
    public void BrokenHashes_AreRefused(string hash) => WithIkm((_, ikm) =>
    {
        var h = new HashAlgorithmName(hash);
        using var template = SecretTemplate(32);
        Assert.Throws<NotSupportedException>(() => HkdfPkcs11.DeriveKey(h, ikm, 32));
        Assert.Throws<NotSupportedException>(() => HkdfPkcs11.DeriveKey(h, ikm, template));
        Assert.Throws<NotSupportedException>(() => HkdfPkcs11.Extract(h, ikm));
        Assert.Throws<NotSupportedException>(() => HkdfPkcs11.ExtractKey(h, ikm));
        Assert.Throws<NotSupportedException>(() => HkdfPkcs11.Expand(h, ikm, 32));
        Assert.Throws<NotSupportedException>(() => HkdfPkcs11.ExpandKey(h, ikm, template));
    });

    [Fact]
    public void AKeyThatIsNotGenericSecretOrHkdf_IsRefused()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label("aes").Value(new byte[32]).Derive().Build();
        using var aes = workspace.ImportKey(tpl);
        using var template = SecretTemplate(32);

        Assert.Equal("ikm", Assert.Throws<ArgumentException>(() => HkdfPkcs11.DeriveKey(Sha256, aes, 32)).ParamName);
        Assert.Equal("ikm", Assert.Throws<ArgumentException>(() => HkdfPkcs11.DeriveKey(Sha256, aes, template)).ParamName);
        Assert.Equal("ikm", Assert.Throws<ArgumentException>(() => HkdfPkcs11.Extract(Sha256, aes)).ParamName);
        Assert.Equal("ikm", Assert.Throws<ArgumentException>(() => HkdfPkcs11.ExtractKey(Sha256, aes)).ParamName);
        Assert.Equal("prk", Assert.Throws<ArgumentException>(() => HkdfPkcs11.Expand(Sha256, aes, 32)).ParamName);
        Assert.Equal("prk", Assert.Throws<ArgumentException>(() => HkdfPkcs11.ExpandKey(Sha256, aes, template)).ParamName);
    }

    [Fact]
    public void AnHkdfKeyType_IsAccepted()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_HKDF).Label("hkdf").Value(Ikm).Derive().Build();
        using var ikm = workspace.ImportKey(tpl);
        using var template = SecretTemplate(32);

        using Pkcs11Key derived = HkdfPkcs11.DeriveKey(Sha256, ikm, template, Salt, Info);
        Assert.Equal(HKDF.DeriveKey(Sha256, Ikm, 32, Salt, Info), ValueOf(derived));
    }

    [Fact]
    public void OnTokenOverloads_NullArguments_Throw() => WithIkm((_, ikm) =>
    {
        using var template = SecretTemplate(32);
        Assert.Equal("ikm", Assert.Throws<ArgumentNullException>(() => HkdfPkcs11.DeriveKey(Sha256, null!, template)).ParamName);
        Assert.Equal("template", Assert.Throws<ArgumentNullException>(() => HkdfPkcs11.DeriveKey(Sha256, ikm, (ObjectTemplate)null!)).ParamName);
        Assert.Equal("ikm", Assert.Throws<ArgumentNullException>(() => HkdfPkcs11.ExtractKey(Sha256, null!)).ParamName);
        Assert.Equal("prk", Assert.Throws<ArgumentNullException>(() => HkdfPkcs11.ExpandKey(Sha256, null!, template)).ParamName);
        Assert.Equal("template", Assert.Throws<ArgumentNullException>(() => HkdfPkcs11.ExpandKey(Sha256, ikm, null!)).ParamName);
        Assert.Equal("ikm", Assert.Throws<ArgumentNullException>(() => HkdfPkcs11.DeriveKey(Sha256, null!, new byte[16], Salt, Info)).ParamName);
        Assert.Equal("ikm", Assert.Throws<ArgumentNullException>(() => HkdfPkcs11.Extract(Sha256, null!, Salt, new byte[32])).ParamName);
        Assert.Equal("prk", Assert.Throws<ArgumentNullException>(() => HkdfPkcs11.Expand(Sha256, null!, new byte[16], Info)).ParamName);
    });
}
