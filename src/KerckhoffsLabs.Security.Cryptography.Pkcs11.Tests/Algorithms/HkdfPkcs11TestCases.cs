using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic <see cref="HkdfPkcs11"/> tests, cross-checked against the BCL <see cref="HKDF"/>.
/// The byte-returning cases read the derived value back, which NSS refuses (see
/// <c>NssBackendFixture.ExtractableDeriveAvailable</c>). The <c>*ViaSignProbe</c> cases prove the
/// on-token overloads without reading anything back: they derive a non-extractable <c>CKA_SIGN</c> key,
/// HMAC-sign a probe message with it on the token, and compare with the MAC the BCL-derived bytes give —
/// the technique <c>HkdfTestCases</c> uses for the raw mechanism.
/// </summary>
internal static class HkdfPkcs11TestCases
{
    private static readonly byte[] Ikm = Convert.FromHexString("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
    private static readonly byte[] Salt = Convert.FromHexString("000102030405060708090A0B0C");
    private static readonly byte[] Info = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9");
    private static readonly byte[] ProbeMessage = "hkdf-adapter-sign-probe"u8.ToArray();
    private static readonly HashAlgorithmName Sha256 = HashAlgorithmName.SHA256;

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    // Imports value as a derive-capable generic-secret key. allowExport opens the scoped override the
    // byte-returning overloads need; the on-token overloads run without it.
    private static void WithKey(IPkcs11Backend backend, byte[] value, bool allowExport, Action<Pkcs11Workspace, Pkcs11Key> body)
    {
        backend.RequireMechanism(CKM.CKM_HKDF_DERIVE);
        using var workspace = backend.OpenWorkspace();
        string label = $"hkdf-adapter-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(value).Derive().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            if (!allowExport)
            {
                body(workspace, key);
                return;
            }
            using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
            body(workspace, key);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    private static byte[] Probe(Pkcs11Key derived)
    {
        byte[] mac = derived.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), ProbeMessage);
        derived.Destroy();
        return mac;
    }

    private static ObjectTemplate SignTemplate(int length) =>
        ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(length).Sign().Build();

    // === Byte results (read back) ==========================================================

    internal static void Assert_DeriveKey_MatchesBcl(IPkcs11Backend backend) =>
        WithKey(backend, Ikm, allowExport: true, (_, ikm) =>
            Assert.Equal(HKDF.DeriveKey(Sha256, Ikm, 42, Salt, Info), HkdfPkcs11.DeriveKey(Sha256, ikm, 42, Salt, Info)));

    internal static void Assert_DeriveKey_NullSalt_MatchesBcl(IPkcs11Backend backend) =>
        WithKey(backend, Ikm, allowExport: true, (_, ikm) =>
            Assert.Equal(HKDF.DeriveKey(Sha256, Ikm, 32, info: Info), HkdfPkcs11.DeriveKey(Sha256, ikm, 32, info: Info)));

    internal static void Assert_Extract_MatchesBcl(IPkcs11Backend backend) =>
        WithKey(backend, Ikm, allowExport: true, (_, ikm) =>
            Assert.Equal(HKDF.Extract(Sha256, Ikm, Salt), HkdfPkcs11.Extract(Sha256, ikm, Salt)));

    internal static void Assert_Expand_MatchesBcl(IPkcs11Backend backend)
    {
        byte[] prkBytes = HKDF.Extract(Sha256, Ikm, Salt);
        WithKey(backend, prkBytes, allowExport: true, (_, prk) =>
            Assert.Equal(HKDF.Expand(Sha256, prkBytes, 50, Info), HkdfPkcs11.Expand(Sha256, prk, 50, Info)));
    }

    // === On-token results (sign probe, no read-back, default policy) ========================

    internal static void Assert_DeriveKey_OnToken_MatchesBclViaSignProbe(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        WithKey(backend, Ikm, allowExport: false, (_, ikm) =>
        {
            byte[] expected = HMACSHA256.HashData(HKDF.DeriveKey(Sha256, Ikm, 32, Salt, Info), ProbeMessage);
            using var template = SignTemplate(32);
            using Pkcs11Key derived = HkdfPkcs11.DeriveKey(Sha256, ikm, template, Salt, Info);
            Assert.Equal(expected, Probe(derived));
        });
    }

    internal static void Assert_ExtractKey_ThenExpandKey_MatchesBclViaSignProbe(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        WithKey(backend, Ikm, allowExport: false, (_, ikm) =>
        {
            byte[] expected = HMACSHA256.HashData(HKDF.DeriveKey(Sha256, Ikm, 32, Salt, Info), ProbeMessage);
            using Pkcs11Key prk = HkdfPkcs11.ExtractKey(Sha256, ikm, Salt);
            try
            {
                using var template = SignTemplate(32);
                using Pkcs11Key okm = HkdfPkcs11.ExpandKey(Sha256, prk, template, Info);
                Assert.Equal(expected, Probe(okm));
            }
            finally { prk.Destroy(); }
        });
    }

    // The PRK ExtractKey returns is sensitive and non-extractable: a real token must not reveal it.
    internal static void Assert_ExtractKey_IsNotReadable(IPkcs11Backend backend) =>
        WithKey(backend, Ikm, allowExport: false, (_, ikm) =>
        {
            using Pkcs11Key prk = HkdfPkcs11.ExtractKey(Sha256, ikm, Salt);
            try
            {
                using var attrs = prk.GetAttributeValue(CKA.CKA_VALUE);
                Assert.True(attrs.Count == 0 || attrs[0].CannotBeRead);
            }
            finally { prk.Destroy(); }
        });

    // Refused by the policy before any derivation, so this holds on every backend with HKDF.
    internal static void Assert_ByteResults_AreRefusedUnderTheDefaultPolicy(IPkcs11Backend backend) =>
        WithKey(backend, Ikm, allowExport: false, (_, ikm) =>
        {
            Assert.Throws<CryptoPolicyViolationException>(() => HkdfPkcs11.DeriveKey(Sha256, ikm, 32, Salt, Info));
            Assert.Throws<CryptoPolicyViolationException>(() => HkdfPkcs11.Extract(Sha256, ikm, Salt));
        });
}
