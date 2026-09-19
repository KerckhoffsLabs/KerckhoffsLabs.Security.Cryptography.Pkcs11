using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>
/// Real-backend coverage for the IKE-derive family (<c>CKM_IKE_PRF_DERIVE</c>,
/// <c>CKM_IKE1_PRF_DERIVE</c>, <c>CKM_IKE1_EXTENDED_DERIVE</c>, <c>CKM_IKE2_PRF_PLUS_DERIVE</c> —
/// PKCS#11 v3.0). NSS's <c>sftkike.c</c> and Kryoptic's <c>ike.rs</c> (since kryoptic v1.5.2+52,
/// which added a real implementation — SoftHSM2, opencryptoki, and pkcs11-mock still lack one) are
/// the two vendored implementations; every one of the four functions is a plain HMAC construction
/// over a documented concatenation of inputs (RFC 2409/7296), so each case here reproduces that
/// exact construction with the BCL's <see cref="HMACSHA256"/> as an independent reference — a
/// genuine known-answer cross-check, not just "the call didn't throw". The base key passed to
/// <see cref="Pkcs11Key.Derive(Mechanism, ObjectTemplate)"/> is imported as
/// <see cref="CKK.CKK_SHA256_HMAC"/>, not <see cref="CKK.CKK_GENERIC_SECRET"/>: PKCS#11 v3.0
/// §6.64.3/.4/.6/.7 require the base key's <c>CKA_KEY_TYPE</c> to match the mechanism's
/// <c>prfMechanism</c> parameter exactly (generic secret is explicitly not admitted) whenever
/// <c>bDataAsKey</c> is false, and Kryoptic enforces this strictly — NSS does not check the base
/// key's type at all, which is why this went unnoticed before Kryoptic grew a real implementation.
/// The <c>hKeygxy</c>/<c>hPrevKey</c>/<c>hSeedKey</c> ancillary keys are unaffected and stay
/// <see cref="CKK.CKK_GENERIC_SECRET"/>, matching what both backends expect for those.
/// <list type="bullet">
/// <item><c>CKM_IKE_PRF_DERIVE</c> (data-as-key = false, rekey = false):
/// <c>HMAC(inKey, Ni ‖ Nr)</c>.</item>
/// <item><c>CKM_IKE1_PRF_DERIVE</c> (no previous key): <c>HMAC(inKey, gxy ‖ CKY_I ‖ CKY_R ‖
/// keyNumber)</c>.</item>
/// <item><c>CKM_IKE1_EXTENDED_DERIVE</c> (RFC 2409 Appendix B, forced into the chaining path via
/// non-empty extra data): <c>K1 = HMAC(K, extra)</c>, <c>K2 = HMAC(K, K1 ‖ extra)</c>, requesting two
/// PRF blocks so the chaining is actually exercised rather than the single-block case.</item>
/// <item><c>CKM_IKE2_PRF_PLUS_DERIVE</c> (RFC 7296 §2.13 prf+, no seed key): <c>T1 = HMAC(K, S ‖
/// 0x01)</c>, <c>T2 = HMAC(K, T1 ‖ S ‖ 0x02)</c>, requesting a length between one and two PRF blocks
/// so the final-block truncation is exercised too.</item>
/// </list>
/// NSS derives only non-extractable keys (a deliberate policy against exposing derived key material —
/// the same limitation that permanently gates <c>HkdfTests.Nss.cs</c>'s read-back cases), so these
/// cases are gated on <see cref="NssBackendFixture.ExtractableDeriveAvailable"/> rather than plain
/// <see cref="NssBackendFixture.NssAvailable"/>.
///
/// The <c>*_MatchesBclViaSignProbe</c> cases below prove the same thing without ever reading the
/// derived key back: derive it non-extractable (granting <c>CKA_SIGN</c> instead of
/// <c>CKA_EXTRACTABLE</c>), then HMAC-sign a fixed probe message with it on the token and compare
/// against the MAC the independent BCL reference bytes would produce for that same message. A
/// mismatch in even one derived bit changes the MAC with overwhelming probability, so this is a
/// genuine cross-check, not merely "the call didn't throw" — and unlike the read-back cases above,
/// it runs on every backend that derives at all, including NSS. Mirrors how
/// <c>DeriveSharedSecretEcdhTests</c> proves ECDH-derived AES keys match via a cross-party AES-GCM
/// round trip instead of reading the raw key.
/// </summary>
internal static class IkeDeriveTestCases
{
    private const int Sha256Size = 32;
    private static readonly byte[] ProbeMessage = "ike-derive-sign-probe"u8.ToArray();

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    private static Pkcs11Key ImportSecret(Pkcs11Workspace workspace, byte[] value, string label, bool derive,
        CKK keyType = CKK.CKK_GENERIC_SECRET)
    {
        var builder = ObjectTemplate.ForSecretKey(keyType).Label(label).Value(value);
        using var tpl = (derive ? builder.Derive() : builder).Build();
        return workspace.ImportKey(tpl);
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
    // triggers the AllowInsecure gate) and immediately signs ProbeMessage with it, never reading
    // CKA_VALUE at all.
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

    internal static void Assert_IkePrf_MatchesReference(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_IKE_PRF_DERIVE);
        using var workspace = backend.OpenWorkspace();
        // Reading the derived key's raw value back (Sensitive(false) in DeriveAndReadValue) is the
        // cross-check itself, so AllowInsecure is required — same reasoning as HkdfTestCases.
        workspace.AllowInsecure = true;
        byte[] inKey = RandomNumberGenerator.GetBytes(32);
        byte[] ni = RandomNumberGenerator.GetBytes(16);
        byte[] nr = RandomNumberGenerator.GetBytes(16);

        // Case 2 from sftk_ike_prf's own doc comment: bDataAsKey = false, bRekey = false ->
        // prf(inKey, Ni || Nr). The output is always exactly one PRF block long — the module ignores
        // any requested length here.
        byte[] niNr = [.. ni, .. nr];
        byte[] expected = HMACSHA256.HashData(inKey, niNr);

        string label = $"ike-prf-{Guid.NewGuid():N}";
        try
        {
            using var baseKey = ImportSecret(workspace, inKey, label, derive: true, keyType: CKK.CKK_SHA256_HMAC);
            var mechanism = new Mechanism(CKM.CKM_IKE_PRF_DERIVE,
                new CkmIkePrfDeriveParams(CKM.CKM_SHA256_HMAC, dataAsKey: false, rekey: false, ni, nr, newKey: 0));

            byte[] actual = DeriveAndReadValue(baseKey, mechanism, Sha256Size);
            Assert.Equal(expected, actual);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_Ike1Prf_MatchesReference(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_IKE1_PRF_DERIVE);
        using var workspace = backend.OpenWorkspace();
        // Reading the derived key's raw value back (Sensitive(false) in DeriveAndReadValue) is the
        // cross-check itself, so AllowInsecure is required — same reasoning as HkdfTestCases.
        workspace.AllowInsecure = true;
        byte[] inKey = RandomNumberGenerator.GetBytes(32);
        byte[] gxy = RandomNumberGenerator.GetBytes(24);
        byte[] ckyI = RandomNumberGenerator.GetBytes(8);
        byte[] ckyR = RandomNumberGenerator.GetBytes(8);
        const byte keyNumber = 0;

        // RFC 2409 §5: outKey = prf(inKey, gxy || CKY_I || CKY_R || keyNumber), no previous key.
        byte[] gxyCkyICkyRNum = [.. gxy, .. ckyI, .. ckyR, keyNumber];
        byte[] expected = HMACSHA256.HashData(inKey, gxyCkyICkyRNum);

        string baseLabel = $"ike1-prf-base-{Guid.NewGuid():N}";
        string gxyLabel = $"ike1-prf-gxy-{Guid.NewGuid():N}";
        try
        {
            using var baseKey = ImportSecret(workspace, inKey, baseLabel, derive: true, keyType: CKK.CKK_SHA256_HMAC);
            using var gxyKey = ImportSecret(workspace, gxy, gxyLabel, derive: false);
            var mechanism = new Mechanism(CKM.CKM_IKE1_PRF_DERIVE,
                new CkmIke1PrfDeriveParams(CKM.CKM_SHA256_HMAC, hasPrevKey: false,
                    gxyKey.PrivateHandle.ObjectId, prevKey: 0, ckyI, ckyR, keyNumber));

            byte[] actual = DeriveAndReadValue(baseKey, mechanism, Sha256Size);
            Assert.Equal(expected, actual);
        }
        finally
        {
            DestroyByLabel(workspace, baseLabel);
            DestroyByLabel(workspace, gxyLabel);
        }
    }

    internal static void Assert_Ike1ExtendedDerive_MatchesReference(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_IKE1_EXTENDED_DERIVE);
        using var workspace = backend.OpenWorkspace();
        // Reading the derived key's raw value back (Sensitive(false) in DeriveAndReadValue) is the
        // cross-check itself, so AllowInsecure is required — same reasoning as HkdfTestCases.
        workspace.AllowInsecure = true;
        byte[] inKey = RandomNumberGenerator.GetBytes(32);
        byte[] extraData = RandomNumberGenerator.GetBytes(20);

        // RFC 2409 Appendix B, forced into the chaining path by non-empty extra data (otherwise a
        // requested length no longer than inKey just subsets it, never touching the PRF at all):
        // K1 = prf(K, extra), K2 = prf(K, K1 || extra). Requesting two full blocks exercises the
        // Kn = prf(K, K(n-1) || extra) chaining, not just the single-block K1 case.
        byte[] k1 = HMACSHA256.HashData(inKey, extraData);
        byte[] k1ExtraData = [.. k1, .. extraData];
        byte[] k2 = HMACSHA256.HashData(inKey, k1ExtraData);
        byte[] expected = [.. k1, .. k2];

        string label = $"ike1-ext-{Guid.NewGuid():N}";
        try
        {
            using var baseKey = ImportSecret(workspace, inKey, label, derive: true, keyType: CKK.CKK_SHA256_HMAC);
            var mechanism = new Mechanism(CKM.CKM_IKE1_EXTENDED_DERIVE,
                new CkmIke1ExtendedDeriveParams(CKM.CKM_SHA256_HMAC, hasKeygxy: false, keygxy: 0, extraData));

            byte[] actual = DeriveAndReadValue(baseKey, mechanism, expected.Length);
            Assert.Equal(expected, actual);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_Ike2PrfPlusDerive_MatchesReference(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_IKE2_PRF_PLUS_DERIVE);
        using var workspace = backend.OpenWorkspace();
        // Reading the derived key's raw value back (Sensitive(false) in DeriveAndReadValue) is the
        // cross-check itself, so AllowInsecure is required — same reasoning as HkdfTestCases.
        workspace.AllowInsecure = true;
        byte[] inKey = RandomNumberGenerator.GetBytes(32);
        byte[] seedData = RandomNumberGenerator.GetBytes(24);
        const int outputLength = Sha256Size + 16; // between one and two PRF blocks: exercises truncation

        // RFC 7296 §2.13 prf+: T1 = prf(K, S || 0x01), T2 = prf(K, T1 || S || 0x02), ..., truncated to
        // the requested length. S is seedData alone here (no seed key).
        byte[] seedData1 = [.. seedData, 0x01];
        byte[] t1 = HMACSHA256.HashData(inKey, seedData1);
        byte[] t1SeedData2 = [.. t1, .. seedData, 0x02];
        byte[] t2 = HMACSHA256.HashData(inKey, t1SeedData2);
        byte[] fullOutput = [.. t1, .. t2];
        byte[] expected = fullOutput[..outputLength];

        string label = $"ike2-prfplus-{Guid.NewGuid():N}";
        try
        {
            using var baseKey = ImportSecret(workspace, inKey, label, derive: true, keyType: CKK.CKK_SHA256_HMAC);
            var mechanism = new Mechanism(CKM.CKM_IKE2_PRF_PLUS_DERIVE,
                new CkmIke2PrfPlusDeriveParams(CKM.CKM_SHA256_HMAC, hasSeedKey: false, seedKey: 0, seedData));

            byte[] actual = DeriveAndReadValue(baseKey, mechanism, outputLength);
            Assert.Equal(expected, actual);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // === Sign-probe variants: prove the same derivations without ever reading CKA_VALUE ==========

    internal static void Assert_IkePrf_MatchesBclViaSignProbe(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_IKE_PRF_DERIVE);
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        using var workspace = backend.OpenWorkspace();
        byte[] inKey = RandomNumberGenerator.GetBytes(32);
        byte[] ni = RandomNumberGenerator.GetBytes(16);
        byte[] nr = RandomNumberGenerator.GetBytes(16);

        byte[] niNr = [.. ni, .. nr];
        byte[] expectedDerived = HMACSHA256.HashData(inKey, niNr);
        byte[] expectedMac = ExpectedProbeMac(expectedDerived);

        string label = $"ike-prf-probe-{Guid.NewGuid():N}";
        try
        {
            using var baseKey = ImportSecret(workspace, inKey, label, derive: true, keyType: CKK.CKK_SHA256_HMAC);
            var mechanism = new Mechanism(CKM.CKM_IKE_PRF_DERIVE,
                new CkmIkePrfDeriveParams(CKM.CKM_SHA256_HMAC, dataAsKey: false, rekey: false, ni, nr, newKey: 0));

            byte[] actualMac = DeriveAndProbe(baseKey, mechanism, Sha256Size);
            Assert.Equal(expectedMac, actualMac);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_Ike1Prf_MatchesBclViaSignProbe(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_IKE1_PRF_DERIVE);
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        using var workspace = backend.OpenWorkspace();
        byte[] inKey = RandomNumberGenerator.GetBytes(32);
        byte[] gxy = RandomNumberGenerator.GetBytes(24);
        byte[] ckyI = RandomNumberGenerator.GetBytes(8);
        byte[] ckyR = RandomNumberGenerator.GetBytes(8);
        const byte keyNumber = 0;

        byte[] gxyCkyICkyRNum = [.. gxy, .. ckyI, .. ckyR, keyNumber];
        byte[] expectedDerived = HMACSHA256.HashData(inKey, gxyCkyICkyRNum);
        byte[] expectedMac = ExpectedProbeMac(expectedDerived);

        string baseLabel = $"ike1-prf-probe-base-{Guid.NewGuid():N}";
        string gxyLabel = $"ike1-prf-probe-gxy-{Guid.NewGuid():N}";
        try
        {
            using var baseKey = ImportSecret(workspace, inKey, baseLabel, derive: true, keyType: CKK.CKK_SHA256_HMAC);
            using var gxyKey = ImportSecret(workspace, gxy, gxyLabel, derive: false);
            var mechanism = new Mechanism(CKM.CKM_IKE1_PRF_DERIVE,
                new CkmIke1PrfDeriveParams(CKM.CKM_SHA256_HMAC, hasPrevKey: false,
                    gxyKey.PrivateHandle.ObjectId, prevKey: 0, ckyI, ckyR, keyNumber));

            byte[] actualMac = DeriveAndProbe(baseKey, mechanism, Sha256Size);
            Assert.Equal(expectedMac, actualMac);
        }
        finally
        {
            DestroyByLabel(workspace, baseLabel);
            DestroyByLabel(workspace, gxyLabel);
        }
    }

    internal static void Assert_Ike1ExtendedDerive_MatchesBclViaSignProbe(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_IKE1_EXTENDED_DERIVE);
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        using var workspace = backend.OpenWorkspace();
        byte[] inKey = RandomNumberGenerator.GetBytes(32);
        byte[] extraData = RandomNumberGenerator.GetBytes(20);

        byte[] k1 = HMACSHA256.HashData(inKey, extraData);
        byte[] k1ExtraData = [.. k1, .. extraData];
        byte[] k2 = HMACSHA256.HashData(inKey, k1ExtraData);
        byte[] expectedDerived = [.. k1, .. k2];
        byte[] expectedMac = ExpectedProbeMac(expectedDerived);

        string label = $"ike1-ext-probe-{Guid.NewGuid():N}";
        try
        {
            using var baseKey = ImportSecret(workspace, inKey, label, derive: true, keyType: CKK.CKK_SHA256_HMAC);
            var mechanism = new Mechanism(CKM.CKM_IKE1_EXTENDED_DERIVE,
                new CkmIke1ExtendedDeriveParams(CKM.CKM_SHA256_HMAC, hasKeygxy: false, keygxy: 0, extraData));

            byte[] actualMac = DeriveAndProbe(baseKey, mechanism, expectedDerived.Length);
            Assert.Equal(expectedMac, actualMac);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_Ike2PrfPlusDerive_MatchesBclViaSignProbe(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_IKE2_PRF_PLUS_DERIVE);
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        using var workspace = backend.OpenWorkspace();
        byte[] inKey = RandomNumberGenerator.GetBytes(32);
        byte[] seedData = RandomNumberGenerator.GetBytes(24);
        const int outputLength = Sha256Size + 16;

        byte[] seedData1 = [.. seedData, 0x01];
        byte[] t1 = HMACSHA256.HashData(inKey, seedData1);
        byte[] t1SeedData2 = [.. t1, .. seedData, 0x02];
        byte[] t2 = HMACSHA256.HashData(inKey, t1SeedData2);
        byte[] fullOutput = [.. t1, .. t2];
        byte[] expectedDerived = fullOutput[..outputLength];
        byte[] expectedMac = ExpectedProbeMac(expectedDerived);

        string label = $"ike2-prfplus-probe-{Guid.NewGuid():N}";
        try
        {
            using var baseKey = ImportSecret(workspace, inKey, label, derive: true, keyType: CKK.CKK_SHA256_HMAC);
            var mechanism = new Mechanism(CKM.CKM_IKE2_PRF_PLUS_DERIVE,
                new CkmIke2PrfPlusDeriveParams(CKM.CKM_SHA256_HMAC, hasSeedKey: false, seedKey: 0, seedData));

            byte[] actualMac = DeriveAndProbe(baseKey, mechanism, outputLength);
            Assert.Equal(expectedMac, actualMac);
        }
        finally { DestroyByLabel(workspace, label); }
    }
}
