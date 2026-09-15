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
/// </summary>
internal static class HkdfTestCases
{
    private static readonly byte[] Ikm =
        Convert.FromHexString("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
    private static readonly byte[] Salt = Convert.FromHexString("000102030405060708090A0B0C");
    private static readonly byte[] Info = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9");

    // PKCS#11 v3.0 §2.42.1: CKF_HKDF_SALT_NULL = 1, CKF_HKDF_SALT_DATA = 2, CKF_HKDF_SALT_KEY = 4.
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

    private static void RequireHkdf(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_HKDF_DERIVE))
            Assert.Skip("Backend does not advertise CKM_HKDF_DERIVE.");
    }

    // Imports Ikm as a derive-capable generic-secret base key and hands it (plus the open workspace)
    // to the body. AllowInsecure is required because the cross-check needs to read the derived
    // key's raw value back off the token.
    private static void WithImportedIkm(IPkcs11Backend backend, Action<Pkcs11Workspace, Pkcs11Key> body)
    {
        RequireHkdf(backend);
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
            // Expand-only treats the base key's value directly as the PRK (no Extract step).
            const int length = 32;
            byte[] expected = new byte[length];
            HKDF.Expand(HashAlgorithmName.SHA256, Ikm, expected, Info);

            var mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE,
                new CkmHkdfParams(extract: false, expand: true, CKM.CKM_SHA256_HMAC,
                    SaltData, default, saltKey: 0, Info));

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
}
