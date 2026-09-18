using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>
/// Real-backend coverage for <see cref="CkmHkdfParams"/> (<c>CKM_HKDF_DERIVE</c>, PKCS#11 v3.0):
/// previously exercised only at the unit-marshalling level. Cross-checks the
/// token's derived output byte-for-byte against the independent BCL <see cref="HKDF"/>
/// implementation (RFC 5869) — a genuine known-answer test, not just "the call didn't throw". NSS's
/// softoken and Kryoptic both implement all three <c>SaltType</c> variants and both the combined
/// Extract-and-Expand mode and Expand-only mode; SoftHSM2 and opencryptoki implement neither
/// (verified against their vendored sources), so those skip via the live mechanism-list check.
///
/// The <c>*_MatchesBclViaSignProbe</c> cases prove the same thing without reading the derived key
/// back: derive it non-extractable (<c>CKA_SIGN</c> instead of <c>CKA_EXTRACTABLE</c>), HMAC-sign a
/// fixed probe message with it on the token, and compare against the MAC the independent BCL
/// reference bytes would produce for that same message. A mismatch in even one derived bit changes
/// the MAC with overwhelming probability, so this is a genuine cross-check — and unlike the
/// read-back cases above, it runs on NSS (which refuses to derive an extractable key at all,
/// permanently gating those). Same technique <c>IkeDeriveTestCases</c> uses, itself mirroring how
/// <c>DeriveSharedSecretEcdhTests</c> proves ECDH-derived AES keys match via a cross-party AES-GCM
/// round trip instead of reading the raw key.
/// </summary>
internal static class HkdfTestCases
{
    private static readonly byte[] Ikm =
        Convert.FromHexString("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
    private static readonly byte[] Salt = Convert.FromHexString("000102030405060708090A0B0C");
    private static readonly byte[] Info = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9");
    private static readonly byte[] ProbeMessage = "hkdf-sign-probe"u8.ToArray();

    // PKCS#11 v3.0 §2.42.1: CKF_HKDF_SALT_NULL = 1, CKF_HKDF_SALT_DATA = 2, CKF_HKDF_SALT_KEY = 4.
    private const ulong SaltNull = 1UL;
    private const ulong SaltData = 2UL;

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) => backend.OpenWorkspace();

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    // Imports Ikm as a derive-capable generic-secret base key and hands it (plus the open workspace)
    // to the body. AllowInsecure is required because the cross-check needs to read the derived
    // key's raw value back off the token.
    private static void WithImportedIkm(IPkcs11Backend backend, Action<Pkcs11Workspace, Pkcs11Key> body)
    {
        backend.RequireMechanism(CKM.CKM_HKDF_DERIVE);
        using var workspace = OpenWorkspace(backend);
        workspace.AllowInsecure = true;
        string label = $"hkdf-ikm-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(Ikm).Derive().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var ikmKey = workspace.ImportKey(tpl);
            body(workspace, ikmKey);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    private static byte[] DeriveAndReadValue(Pkcs11Key baseKey, Mechanism mechanism, int outputLength)
    {
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(outputLength).Derive().Extractable().Sensitive(false).Build();

        using Pkcs11Key derived = baseKey.Derive(mechanism, template);
        using var attrs = derived.GetAttributeValue(CKA.CKA_VALUE);
        Assert.False(attrs[0].CannotBeRead);
        byte[] value = attrs[0].GetValueAsByteArray();
        derived.Destroy();
        return value;
    }

    // Derives a non-extractable CKA_SIGN key (no CKA_EXTRACTABLE, default CKA_SENSITIVE — never
    // needs AllowInsecure) and immediately signs ProbeMessage with it, never reading CKA_VALUE.
    private static byte[] DeriveAndProbe(Pkcs11Key baseKey, Mechanism mechanism, int outputLength)
    {
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(outputLength).Sign().Build();

        using Pkcs11Key derived = baseKey.Derive(mechanism, template);
        byte[] mac = derived.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), ProbeMessage);
        derived.Destroy();
        return mac;
    }

    private static byte[] ExpectedProbeMac(byte[] expectedDerivedBytes) =>
        HMACSHA256.HashData(expectedDerivedBytes, ProbeMessage);

    internal static void Assert_ExtractAndExpand_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedIkm(backend, (_, ikmKey) =>
        {
            const int length = 42; // the RFC 5869 test-vector length
            byte[] expected = HKDF.DeriveKey(HashAlgorithmName.SHA256, Ikm, length, Salt, Info);

            var mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE,
                new CkmHkdfParams(extract: true, expand: true, CKM.CKM_SHA256_HMAC,
                    SaltData, Salt, saltKey: 0, Info));

            byte[] actual = DeriveAndReadValue(ikmKey, mechanism, length);

            Assert.Equal(expected, actual);
        });

    internal static void Assert_ExpandOnly_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedIkm(backend, (_, ikmKey) =>
        {
            // Expand-only treats the base key's value directly as the PRK (no Extract step), so the
            // salt is unused — SaltType must be SALT_NULL here, since SALT_DATA with an empty span
            // is a mismatch Kryoptic rejects outright (ulSaltLen == 0 with CKF_HKDF_SALT_DATA).
            const int length = 32;
            byte[] expected = new byte[length];
            HKDF.Expand(HashAlgorithmName.SHA256, Ikm, expected, Info);

            var mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE,
                new CkmHkdfParams(extract: false, expand: true, CKM.CKM_SHA256_HMAC,
                    SaltNull, default, saltKey: 0, Info));

            byte[] actual = DeriveAndReadValue(ikmKey, mechanism, length);

            Assert.Equal(expected, actual);
        });

    internal static void Assert_ExtractOnly_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedIkm(backend, (_, ikmKey) =>
        {
            // Extract-only ignores the requested output length: the result is always one PRF
            // block long (32 bytes for SHA-256).
            byte[] expected = HKDF.Extract(HashAlgorithmName.SHA256, Ikm, Salt);

            var mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE,
                new CkmHkdfParams(extract: true, expand: false, CKM.CKM_SHA256_HMAC,
                    SaltData, Salt, saltKey: 0, default));

            byte[] actual = DeriveAndReadValue(ikmKey, mechanism, expected.Length);

            Assert.Equal(expected, actual);
        });

    // === Sign-probe variants: prove the same derivations without ever reading CKA_VALUE ==========

    internal static void Assert_ExtractAndExpand_MatchesBclViaSignProbe(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        WithImportedIkm(backend, (_, ikmKey) =>
        {
            const int length = 42; // the RFC 5869 test-vector length
            byte[] expectedDerived = HKDF.DeriveKey(HashAlgorithmName.SHA256, Ikm, length, Salt, Info);
            byte[] expectedMac = ExpectedProbeMac(expectedDerived);

            var mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE,
                new CkmHkdfParams(extract: true, expand: true, CKM.CKM_SHA256_HMAC,
                    SaltData, Salt, saltKey: 0, Info));

            byte[] actualMac = DeriveAndProbe(ikmKey, mechanism, length);

            Assert.Equal(expectedMac, actualMac);
        });
    }

    internal static void Assert_ExpandOnly_MatchesBclViaSignProbe(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        WithImportedIkm(backend, (_, ikmKey) =>
        {
            const int length = 32;
            byte[] expectedDerived = new byte[length];
            HKDF.Expand(HashAlgorithmName.SHA256, Ikm, expectedDerived, Info);
            byte[] expectedMac = ExpectedProbeMac(expectedDerived);

            var mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE,
                new CkmHkdfParams(extract: false, expand: true, CKM.CKM_SHA256_HMAC,
                    SaltNull, default, saltKey: 0, Info));

            byte[] actualMac = DeriveAndProbe(ikmKey, mechanism, length);

            Assert.Equal(expectedMac, actualMac);
        });
    }

    internal static void Assert_ExtractOnly_MatchesBclViaSignProbe(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        WithImportedIkm(backend, (_, ikmKey) =>
        {
            byte[] expectedDerived = HKDF.Extract(HashAlgorithmName.SHA256, Ikm, Salt);
            byte[] expectedMac = ExpectedProbeMac(expectedDerived);

            var mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE,
                new CkmHkdfParams(extract: true, expand: false, CKM.CKM_SHA256_HMAC,
                    SaltData, Salt, saltKey: 0, default));

            byte[] actualMac = DeriveAndProbe(ikmKey, mechanism, expectedDerived.Length);

            Assert.Equal(expectedMac, actualMac);
        });
    }
}
