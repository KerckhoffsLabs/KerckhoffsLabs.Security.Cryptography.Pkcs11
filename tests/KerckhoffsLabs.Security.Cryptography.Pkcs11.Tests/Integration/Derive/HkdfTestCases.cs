using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;
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
///
/// <c>Hkdf_ParameterOutOfRange_IsRefused</c> goes through the raw dispatch, with values the library's HKDF API
/// refuses before any native call: an output longer than RFC 5869 allows, and a salt key that is no secret key.
/// </summary>
internal static class HkdfTestCases
{
    private static readonly byte[] Ikm =
        Convert.FromHexString("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
    private static readonly byte[] Salt = Convert.FromHexString("000102030405060708090A0B0C");
    private static readonly byte[] Info = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9");
    private static readonly byte[] ProbeMessage = "hkdf-sign-probe"u8.ToArray();

    private static Pkcs11Session OpenSession(IPkcs11Backend backend) => backend.OpenSession();

    private static void DestroyByLabel(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in session.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    // Imports Ikm as a derive-capable generic-secret base key and hands it (plus the open session)
    // to the body. the AllowInsecure policy is required because the cross-check needs to read the derived
    // key's raw value back off the token.
    private static void WithImportedIkm(IPkcs11Backend backend, Action<Pkcs11Session, Pkcs11Key> body)
    {
        backend.RequireMechanism(CKM.CKM_HKDF_DERIVE);
        using var session = OpenSession(backend);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        string label = $"hkdf-ikm-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(Ikm).Derive().OnToken(backend.SupportsTokenObjects).Build();
        try
        {
            using var ikmKey = session.ImportKey(tpl);
            body(session, ikmKey);
        }
        finally { DestroyByLabel(session, label); }
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
    // needs the AllowInsecure policy) and immediately signs ProbeMessage with it, never reading CKA_VALUE.
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
                CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, Salt, Info));

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
                CkmHkdfParams.WithoutSalt(HkdfOperation.ExpandOnly, CKM.CKM_SHA256, Info));

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
                CkmHkdfParams.WithSalt(HkdfOperation.ExtractOnly, CKM.CKM_SHA256, Salt));

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
                CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, Salt, Info));

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
                CkmHkdfParams.WithoutSalt(HkdfOperation.ExpandOnly, CKM.CKM_SHA256, Info));

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
                CkmHkdfParams.WithSalt(HkdfOperation.ExtractOnly, CKM.CKM_SHA256, Salt));

            byte[] actualMac = DeriveAndProbe(ikmKey, mechanism, expectedDerived.Length);

            Assert.Equal(expectedMac, actualMac);
        });
    }

    // === Parameters out of range, through the raw dispatch ==================================

    public static TheoryData<string> HkdfParameterFaults =>
        ["CKA_VALUE_LEN 255 x 32 + 1", "CKA_VALUE_LEN 2^32 + 1", "a salt key that is an EC public key"];

    // HKDF is RFC 5869's (PKCS#11 v3.2 §6.62.3), whose expand step gives at most 255 x HashLen bytes: with SHA-256,
    // CKA_VALUE_LEN 8161 cannot be met, nor 2^32 + 1 where CK_ULONG is 64 bits (a module that narrows it makes a
    // 1-byte key). C_DeriveKey refuses the length with CKR_ATTRIBUTE_VALUE_INVALID or CKR_TEMPLATE_INCONSISTENT
    // (§4.1, §5.1.6) or CKR_KEY_SIZE_RANGE (§5.18.5). The salt of CKF_HKDF_SALT_KEY is the HMAC key of the extract
    // step, so an EC public key (no CKA_VALUE) cannot be one; §6.62.2 names no code, so CKR_MECHANISM_PARAM_INVALID,
    // CKR_KEY_HANDLE_INVALID or CKR_KEY_TYPE_INCONSISTENT is taken. None makes a key (found by label), and the same
    // session then derives RFC 5869's output for 42 bytes, checked through an HMAC under it where the module has
    // HMAC-SHA256. The base key is a 32-byte generic secret, the hash's size (§6.62.3). The library's HKDF API
    // refuses the lengths, and takes only a key it holds as the salt, before any native call.
    internal static void Assert_Hkdf_ParameterOutOfRange_IsRefused(IPkcs11Backend backend, string fault)
    {
        if (fault.Contains("2^32", StringComparison.Ordinal))
            Assert.SkipUnless(UnmanagedMemory.NativeULongSize == 8, "CK_ULONG is 32 bits on this platform.");
        backend.RequireMechanism(CKM.CKM_HKDF_DERIVE);
        bool saltKeyRow = fault.StartsWith("a salt key", StringComparison.Ordinal);
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
            byte[] ikm = RandomNumberGenerator.GetBytes(32);
            ObjectHandle baseKey = CreateDeriveKey(session, ikm);
            ObjectHandle saltKey = default;
            try
            {
                if (saltKeyRow)
                {
                    using var ec = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                    ECPoint q = ec.ExportParameters(includePrivateParameters: false).Q;
                    saltKey = TestKeys.ImportEcP256PublicKey(session, q.X!, q.Y!);
                }
                using var buffers = new NativeBuffers();
                string label = $"kl-hkdf-param-{Guid.NewGuid():N}";
                ulong valueLen = fault switch
                {
                    "CKA_VALUE_LEN 255 x 32 + 1" => 255 * 32 + 1,
                    "CKA_VALUE_LEN 2^32 + 1" => (1UL << 32) + 1,
                    _ => 42,
                };
                Mechanism bad = saltKeyRow ? RawHkdf(buffers, saltKey) : RawHkdf(buffers, default);
                CKR rv = RawDerive(lowLevel, session, bad, baseKey, valueLen, label, out _);
                CKR[] allowed = saltKeyRow
                    ? [CKR.CKR_MECHANISM_PARAM_INVALID, CKR.CKR_KEY_HANDLE_INVALID, CKR.CKR_KEY_TYPE_INCONSISTENT]
                    : [CKR.CKR_ATTRIBUTE_VALUE_INVALID, CKR.CKR_TEMPLATE_INCONSISTENT, CKR.CKR_KEY_SIZE_RANGE];
                Assert.True(allowed.Contains(rv), $"C_DeriveKey(CKM_HKDF_DERIVE) with {fault} returned {rv}.");
                using (var labelAttribute = new ObjectAttribute(CKA.CKA_LABEL, label))
                    Assert.Empty(session.FindAllObjects([labelAttribute]));

                rv = RawDerive(lowLevel, session, RawHkdf(buffers, default), baseKey, 42, label, out ObjectHandle derived);
                Assert.True(rv == CKR.CKR_OK, $"C_DeriveKey(CKM_HKDF_DERIVE) with good parameters after the refusal returned {rv}.");
                try
                {
                    if (backend.Supports(CKM.CKM_SHA256_HMAC))
                        Assert.Equal(ExpectedProbeMac(HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 42, Salt, Info)),
                            session.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), derived, ProbeMessage));
                }
                finally { session.DestroyObject(derived); }
            }
            finally
            {
                if (!saltKey.IsInvalid)
                    session.DestroyObject(saltKey);
                session.DestroyObject(baseKey);
            }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // For the tripwires: the derivation of Assert_Hkdf_ParameterOutOfRange_IsRefused with one fault, and the
    // CKA_VALUE_LEN of the key made, if one is.
    internal static (CKR Rv, ulong? ValueLen) DeriveHkdfWithFault(IPkcs11Backend backend, string fault)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        ObjectHandle baseKey = CreateDeriveKey(session, RandomNumberGenerator.GetBytes(32));
        ObjectHandle saltKey = default;
        try
        {
            bool saltKeyRow = fault.StartsWith("a salt key", StringComparison.Ordinal);
            if (saltKeyRow)
            {
                using var ec = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                ECPoint q = ec.ExportParameters(includePrivateParameters: false).Q;
                saltKey = TestKeys.ImportEcP256PublicKey(session, q.X!, q.Y!);
            }
            using var buffers = new NativeBuffers();
            ulong valueLen = fault == "CKA_VALUE_LEN 2^32 + 1" ? (1UL << 32) + 1 : fault == "CKA_VALUE_LEN 255 x 32 + 1" ? 255UL * 32 + 1 : 42UL;
            CKR rv = RawDerive(lowLevel, session, RawHkdf(buffers, saltKey), baseKey, valueLen, $"kl-hkdf-probe-{Guid.NewGuid():N}", out ObjectHandle derived);
            if (rv != CKR.CKR_OK)
                return (rv, null);
            try
            {
                using var read = session.GetAttributeValue(derived, [CKA.CKA_VALUE_LEN]);
                return (rv, read[0].GetValueAsUlong());
            }
            finally { session.DestroyObject(derived); }
        }
        finally
        {
            if (!saltKey.IsInvalid)
                session.DestroyObject(saltKey);
            session.DestroyObject(baseKey);
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    private static ObjectHandle CreateDeriveKey(Pkcs11SessionCore session, byte[] value)
    {
        using var keyClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var keyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var derive = new ObjectAttribute(CKA.CKA_DERIVE, true);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, value);
        return session.CreateObject([keyClass, keyType, token, derive, attrValue]);
    }

    // CK_HKDF_PARAMS for extract and expand with SHA-256 and Info: the salt is Salt (CKF_HKDF_SALT_DATA), or the key
    // given (CKF_HKDF_SALT_KEY).
    private static Mechanism RawHkdf(NativeBuffers buffers, ObjectHandle saltKey)
    {
        bool key = !saltKey.IsInvalid;
        var parameter = new CK_HKDF_PARAMS
        {
            Extract = 1,
            Expand = 1,
            PrfHashMechanism = (NativeCULong)(ulong)CKM.CKM_SHA256,
            SaltType = (NativeCULong)(ulong)(key ? HkdfSaltType.Key : HkdfSaltType.Data),
            Salt = key ? IntPtr.Zero : buffers.Of(Salt),
            SaltLen = (NativeCULong)(ulong)(key ? 0 : Salt.Length),
            SaltKey = (NativeCULong)saltKey.ObjectId,
            Info = buffers.Of(Info),
            InfoLen = (NativeCULong)(ulong)Info.Length,
        };
        return RawParameter.From(CKM.CKM_HKDF_DERIVE, in parameter);
    }

    // C_DeriveKey of a session generic secret of valueLen bytes, with the label and CKA_SIGN, through the raw dispatch.
    private static CKR RawDerive(LowLevelPkcs11Library lowLevel, Pkcs11SessionCore session, Mechanism mechanism, ObjectHandle baseKey,
        ulong valueLen, string label, out ObjectHandle derived)
    {
        using var keyClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var keyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var length = new ObjectAttribute(CKA.CKA_VALUE_LEN, valueLen);
        using var sign = new ObjectAttribute(CKA.CKA_SIGN, true);
        using var labelAttribute = new ObjectAttribute(CKA.CKA_LABEL, label);
        using var scope = new MechanismParameterScope();
        CK_MECHANISM mech = mechanism.Marshal(scope, out _);
        CK_ATTRIBUTE[] template = [.. new[] { keyClass, keyType, token, length, sign, labelAttribute }.Select(a => a.CkAttribute)];
        CKR rv = lowLevel.C_DeriveKey((NativeCULong)session.SessionId, in mech, (NativeCULong)baseKey.ObjectId, template, out NativeCULong handle);
        derived = new ObjectHandle((ulong)handle);
        return rv;
    }
}
