using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These tests drive the gated legacy mechanisms/hashes on purpose (the AllowInsecure gate is the
// behaviour under test), so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11010

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic SP800108HmacCounterKdfPkcs11 tests: argument / key-type / PRF-validation / dispose
/// cases run on any backend (they throw before any token call); the known-answer derivations require
/// the token to implement <c>CKM_SP800_108_COUNTER_KDF</c> and skip where it does not (neither SoftHSM
/// nor opencryptoki do today — ready for a capable HSM).
///
/// The <c>*_MatchesBclViaSignProbe</c> case proves the same thing without reading the derived key
/// back: derive it non-extractable (via <see cref="SP800108HmacCounterKdfPkcs11.DeriveKey(ReadOnlySpan{byte}, ReadOnlySpan{byte}, ObjectTemplate)"/>,
/// granting <c>CKA_SIGN</c> instead of <c>CKA_EXTRACTABLE</c>), HMAC-sign a fixed probe message with
/// it on the token, and compare against the MAC the independent BCL-derived bytes would produce for
/// that same message. Same technique <c>HkdfTestCases</c>/<c>IkeDeriveTestCases</c> use.
/// </summary>
internal static class SP800108HmacCounterKdfPkcs11TestCases
{
    private static readonly byte[] KeyBytes =
        Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    private static readonly byte[] Label = Encoding.UTF8.GetBytes("kdf-label");
    private static readonly byte[] Context = Encoding.UTF8.GetBytes("kdf-context");
    private static readonly byte[] ProbeMessage = "sp800-108-sign-probe"u8.ToArray();

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    // Imports KeyBytes as a derive-capable generic-secret base key and hands the KDF to the body.
    private static void WithImportedKdf(IPkcs11Backend backend, Action<Pkcs11Workspace, SP800108HmacCounterKdfPkcs11> body)
    {
        using var workspace = OpenWorkspace(backend);
        // The byte-returning DeriveKey overloads read the derived value off the token, so the gate in
        // BuildSecureKeyDefaults refuses them under the default posture. Opt in here.
        workspace.AllowInsecure = true;
        string label = $"kdf-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(KeyBytes).Derive().Sign().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            using var kdf = new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.SHA256);
            body(workspace, kdf);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // Imports the base key and hands the raw Pkcs11Key (for ctor-validation tests).
    private static void WithImportedKdfKey(IPkcs11Backend backend, Action<Pkcs11Workspace, Pkcs11Key> body)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"kdf-raw-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(KeyBytes).Derive().Sign().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            body(workspace, key);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_Ctor_NonGenericSecretKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"kdf-aes-{Guid.NewGuid():N}";
        byte[] aes = new byte[32];
        RandomNumberGenerator.Fill(aes);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).Value(aes).Derive().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            var ex = Assert.Throws<ArgumentException>(
                () => new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.SHA256));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_Ctor_UnsupportedPrfHash_Throws(IPkcs11Backend backend) =>
        WithImportedKdfKey(backend, (_, key) =>
        {
            Assert.Throws<NotSupportedException>(
                () => new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.SHA1));
            Assert.Throws<NotSupportedException>(
                () => new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.MD5));
        });

    internal static void Assert_DeriveKey_NegativeLength_Throws(IPkcs11Backend backend) =>
        WithImportedKdf(backend, (_, kdf) =>
            Assert.Throws<ArgumentOutOfRangeException>(() => kdf.DeriveKey(Label, Context, -1)));

    internal static void Assert_DeriveKey_ZeroLength_IsNoOp(IPkcs11Backend backend) =>
        WithImportedKdf(backend, (_, kdf) =>
        {
            // Zero length is a no-op, matching the BCL SP800108HmacCounterKdf (no token call).
            Assert.Empty(kdf.DeriveKey(Label, Context, 0));
            kdf.DeriveKey(Label, Context, []); // must not throw
        });

    internal static void Assert_DeriveKey_AfterDispose_Throws(IPkcs11Backend backend) =>
        WithImportedKdf(backend, (_, kdf) =>
        {
            kdf.Dispose();
            Assert.Throws<ObjectDisposedException>(() => kdf.DeriveKey(Label, Context, 16));
        });

    // === Known-answer derivations (require token SP800-108 support) =================================

    internal static void Assert_DeriveKey_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedKdf(backend, (_, kdf) =>
        {
            backend.RequireMechanism(CKM.CKM_SP800_108_COUNTER_KDF);
            const int length = 40; // spans two HMAC-SHA256 PRF blocks (32 bytes each)
            byte[] expected = SP800108HmacCounterKdf.DeriveBytes(
                KeyBytes, HashAlgorithmName.SHA256, Label, Context, length);

            byte[] actual = kdf.DeriveKey(Label, Context, length);

            Assert.Equal(expected, actual);
        });

    internal static void Assert_DeriveKey_DestinationSpan_MatchesBcl(IPkcs11Backend backend) =>
        WithImportedKdf(backend, (_, kdf) =>
        {
            backend.RequireMechanism(CKM.CKM_SP800_108_COUNTER_KDF);
            const int length = 32;
            byte[] expected = SP800108HmacCounterKdf.DeriveBytes(
                KeyBytes, HashAlgorithmName.SHA256, Label, Context, length);

            byte[] actual = new byte[length];
            kdf.DeriveKey(Label, Context, actual);

            Assert.Equal(expected, actual);
        });

    // Derives a non-extractable CKA_SIGN key (no CKA_EXTRACTABLE, default CKA_SENSITIVE — never
    // needs AllowInsecure for this part) and immediately signs ProbeMessage with it, never reading
    // CKA_VALUE.
    private static byte[] DeriveAndProbe(SP800108HmacCounterKdfPkcs11 kdf, int outputLength)
    {
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(outputLength).Sign().Build();

        using Pkcs11Key derived = kdf.DeriveKey(Label, Context, template);
        byte[] mac = derived.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), ProbeMessage);
        derived.Destroy();
        return mac;
    }

    internal static void Assert_DeriveKey_MatchesBclViaSignProbe(IPkcs11Backend backend) =>
        WithImportedKdf(backend, (_, kdf) =>
        {
            backend.RequireMechanism(CKM.CKM_SP800_108_COUNTER_KDF);
            backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
            const int length = 40; // spans two HMAC-SHA256 PRF blocks (32 bytes each)
            byte[] expectedDerived = SP800108HmacCounterKdf.DeriveBytes(
                KeyBytes, HashAlgorithmName.SHA256, Label, Context, length);
            byte[] expectedMac = HMACSHA256.HashData(expectedDerived, ProbeMessage);

            byte[] actualMac = DeriveAndProbe(kdf, length);

            Assert.Equal(expectedMac, actualMac);
        });

    internal static void Assert_DeriveKey_OnToken_ReturnsNonExtractableKey(IPkcs11Backend backend) =>
        WithImportedKdf(backend, (_, kdf) =>
        {
            backend.RequireMechanism(CKM.CKM_SP800_108_COUNTER_KDF);
            using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
                .ValueLen(32).Derive().NonExtractable().Sensitive().Build();

            using Pkcs11Key derived = kdf.DeriveKey(Label, Context, template);
            try
            {
                // The derived sub-key is sensitive and non-extractable, so its value must not be
                // readable. A token may answer either by omitting the attribute or by returning it
                // unreadable, so both count.
                using var attrs = derived.GetAttributeValue(CKA.CKA_VALUE);
                Assert.True(attrs.Count == 0 || attrs[0].CannotBeRead);
            }
            finally
            {
                derived.Destroy();
            }
        });
}
