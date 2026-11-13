using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These cases derive with mechanisms outside the default policy (digests as KDFs, ECB, string-data derivation) on
// purpose, under a scoped AllowInsecure lease; the compile-time policy analyzer flags them, so its warnings are
// suppressed for this file only.
#pragma warning disable KLPKCS11008, KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

// Key derivation by a digest, by an encryption, by concatenation, by XOR and by extraction.
internal static partial class MechanismCoverageTestCases
{
    private static readonly byte[] BaseSecret = [.. Enumerable.Range(0, 32).Select(i => (byte)(0xA0 + i))];
    private static readonly byte[] DerivationData = [.. Enumerable.Range(0, 32).Select(i => (byte)(0x10 + 3 * i))];

    public static TheoryData<string> KeyDerivationFamilies => FamiliesWhere(f => f.KeyDerivation is not null);

    // A CK_KEY_DERIVATION_STRING_DATA naming data the caller keeps alive in buffers until the call returns.
    private static Mechanism StringData(CKM type, NativeBuffers buffers, byte[] data)
        => RawParameter.From(type, new CK_KEY_DERIVATION_STRING_DATA { Data = buffers.Of(data), Len = (NativeCULong)(ulong)data.Length });

    // Derives from a generic base secret and compares the derived key with the expected value through an HMAC.
    private static void AssertDerivesFromGenericSecret(IPkcs11Backend backend, byte[] baseValue, Func<NativeBuffers, Mechanism> mechanism,
        byte[] expected, string what, string? notTakenBecause = null)
    {
        WithSession(backend, session =>
        {
            ObjectHandle baseKey = CreateSecret(session, CKK.CKK_GENERIC_SECRET, baseValue, CKA.CKA_DERIVE);
            try
            {
                using var buffers = new NativeBuffers();
                byte[] mac = Taken(() => HmacOfDerived(session, mechanism(buffers), baseKey, (ulong)expected.Length), what, notTakenBecause);
                Assert.Equal(HMACSHA256.HashData(expected, Message), mac);
            }
            finally { session.DestroyObject(baseKey); }
        });
    }

    // === Digest derivation ======================================================

    // A digest derivation (PKCS#11 v3.2, the digest key derivation mechanisms) gives the digest of the base key's value; asked for
    // fewer bytes, the leading bytes of it.
    internal static void Assert_DigestKeyDerivation_IsTheDigestOfTheBaseKey(IPkcs11Backend backend, string familyName)
    {
        HashFamily family = Family(familyName);
        CKM derivation = family.KeyDerivation!.Value;
        if (family.Bcl is null)
            backend.RequireMechanisms(derivation, family.Digest, CKM.CKM_SHA256_HMAC);
        else
            backend.RequireMechanisms(derivation, CKM.CKM_SHA256_HMAC);
        byte[] digest = [];
        WithSession(backend, session => digest = HashOf(session, family)(BaseSecret));
        foreach (int length in new[] { family.Size, family.Size / 2 }.Distinct())
            AssertDerivesFromGenericSecret(backend, BaseSecret, _ => new Mechanism(derivation), digest[..length], $"{derivation} for {length} bytes");
    }

    // The SHAKE derivations (PKCS#11 v3.2) give the extendable output of the base key's value, as many bytes
    // as CKA_VALUE_LEN asks for: shorter and longer than the hash's own security strength.
    public static TheoryData<CKM, int> ShakeDerivations => new()
    {
        { CKM.CKM_SHAKE_128_KEY_DERIVATION, 16 }, { CKM.CKM_SHAKE_128_KEY_DERIVATION, 32 }, { CKM.CKM_SHAKE_128_KEY_DERIVATION, 64 },
        { CKM.CKM_SHAKE_256_KEY_DERIVATION, 32 }, { CKM.CKM_SHAKE_256_KEY_DERIVATION, 64 }, { CKM.CKM_SHAKE_256_KEY_DERIVATION, 96 },
    };

    internal static void Assert_ShakeKeyDerivation_IsTheXofOfTheBaseKey(IPkcs11Backend backend, CKM mechanism, int length, string? notTakenBecause = null)
    {
        backend.RequireMechanisms(mechanism, CKM.CKM_SHA256_HMAC);
        bool shake128 = mechanism == CKM.CKM_SHAKE_128_KEY_DERIVATION;
        Assert.SkipUnless(shake128 ? Shake128.IsSupported : Shake256.IsSupported, "The runtime has no SHAKE to compare with.");
        byte[] expected = shake128 ? Shake128.HashData(BaseSecret, length) : Shake256.HashData(BaseSecret, length);
        AssertDerivesFromGenericSecret(backend, BaseSecret, _ => new Mechanism(mechanism), expected, $"{mechanism} for {length} bytes", notTakenBecause);
    }

    // === Derivation by encryption ===============================================

    // CKM_AES_ECB_ENCRYPT_DATA takes a CK_KEY_DERIVATION_STRING_DATA and gives the AES-ECB encryption of its data
    // under the base key; CKM_AES_CBC_ENCRYPT_DATA takes a CK_AES_CBC_ENCRYPT_DATA_PARAMS and gives the AES-CBC
    // encryption under its IV (PKCS#11 v3.2, the AES key derivation mechanisms), each without padding.
    internal static void Assert_AesEncryptData_IsTheEncryptionOfTheData(IPkcs11Backend backend, CKM mechanism)
    {
        backend.RequireMechanisms(mechanism, CKM.CKM_SHA256_HMAC);
        byte[] aesKey = BaseSecret;
        using var aes = Aes.Create();
        aes.Key = aesKey;
        byte[] expected = mechanism == CKM.CKM_AES_ECB_ENCRYPT_DATA
            ? aes.EncryptEcb(DerivationData, PaddingMode.None)
            : aes.EncryptCbc(DerivationData, Iv16, PaddingMode.None);
        AssertDerivesByEncryption(backend, CKK.CKK_AES, aesKey, mechanism, expected);
    }

    // RFC 3713 §A key and a 32-byte plaintext; the ciphertexts were computed with OpenSSL, whose Camellia gives the
    // three RFC 3713 vectors.
    private static readonly byte[] CamelliaKey = Convert.FromHexString("0123456789abcdeffedcba9876543210");
    private static readonly byte[] CamelliaPlaintext = "the quick brown fox jumps over t"u8.ToArray();
    private static readonly byte[] CamelliaEcbCiphertext = Convert.FromHexString("441b8d9f7e922ff810a67582100599a7955a8efb2cf3780398f3e9f1caceabed");
    private static readonly byte[] CamelliaCbcCiphertext = Convert.FromHexString("caa77d1719b0f1b7b9bd801e637bad42b4968cd68fe4921065c87e393ff56873");

    // CKM_CAMELLIA_ECB_ENCRYPT_DATA and CKM_CAMELLIA_CBC_ENCRYPT_DATA (PKCS#11 v3.2) as the AES ones.
    internal static void Assert_CamelliaEncryptData_IsTheEncryptionOfTheData(IPkcs11Backend backend, CKM mechanism)
    {
        backend.RequireMechanisms(mechanism, CKM.CKM_SHA256_HMAC);
        byte[] expected = mechanism == CKM.CKM_CAMELLIA_ECB_ENCRYPT_DATA ? CamelliaEcbCiphertext : CamelliaCbcCiphertext;
        AssertDerivesByEncryption(backend, CKK.CKK_CAMELLIA, CamelliaKey, mechanism, expected, CamelliaPlaintext);
    }

    private static void AssertDerivesByEncryption(IPkcs11Backend backend, CKK keyType, byte[] key, CKM mechanism, byte[] expected, byte[]? data = null)
    {
        data ??= DerivationData;
        WithSession(backend, session =>
        {
            ObjectHandle baseKey = CreateSecret(session, keyType, key, CKA.CKA_DERIVE);
            try
            {
                using var buffers = new NativeBuffers();
                Mechanism derive = mechanism switch
                {
                    CKM.CKM_AES_CBC_ENCRYPT_DATA or CKM.CKM_CAMELLIA_CBC_ENCRYPT_DATA => CbcEncryptData(mechanism, buffers, data),
                    _ => StringData(mechanism, buffers, data),
                };
                byte[] mac = Taken(() => HmacOfDerived(session, derive, baseKey, (ulong)expected.Length), $"{mechanism}");
                Assert.Equal(HMACSHA256.HashData(expected, Message), mac);
            }
            finally { session.DestroyObject(baseKey); }
        });
    }

    // A CK_AES_CBC_ENCRYPT_DATA_PARAMS or CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS: the IV inline, then the data.
    private static Mechanism CbcEncryptData(CKM type, NativeBuffers buffers, byte[] data)
    {
        if (type == CKM.CKM_AES_CBC_ENCRYPT_DATA)
        {
            var aes = new CK_AES_CBC_ENCRYPT_DATA_PARAMS { Data = buffers.Of(data), Length = (NativeCULong)(ulong)data.Length };
            Iv16.CopyTo((Span<byte>)aes.Iv);
            return RawParameter.From(type, aes);
        }
        var camellia = new CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS { Data = buffers.Of(data), Length = (NativeCULong)(ulong)data.Length };
        Iv16.CopyTo((Span<byte>)camellia.Iv);
        return RawParameter.From(type, camellia);
    }

    // === Concatenation, XOR and extraction ======================================

    private static readonly byte[] SecondSecret = [.. Enumerable.Range(0, 16).Select(i => (byte)(0x55 ^ i))];
    private static readonly byte[] ShortData = [.. Enumerable.Range(0, 16).Select(i => (byte)(0x13 + 7 * i))];

    // CKM_CONCATENATE_BASE_AND_KEY takes the second key's handle and gives the base key's value followed by the
    // second key's (PKCS#11 v3.2, the miscellaneous simple key derivation mechanisms).
    internal static void Assert_ConcatenateBaseAndKey_IsBothValues(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_CONCATENATE_BASE_AND_KEY, CKM.CKM_SHA256_HMAC);
        WithSession(backend, session =>
        {
            ObjectHandle baseKey = CreateSecret(session, CKK.CKK_GENERIC_SECRET, BaseSecret, CKA.CKA_DERIVE);
            ObjectHandle second = CreateSecret(session, CKK.CKK_GENERIC_SECRET, SecondSecret, CKA.CKA_DERIVE);
            try
            {
                byte[] expected = [.. BaseSecret, .. SecondSecret];
                var mechanism = new Mechanism(CKM.CKM_CONCATENATE_BASE_AND_KEY, NativeULong(second.ObjectId));
                Assert.Equal(HMACSHA256.HashData(expected, Message),
                    Taken(() => HmacOfDerived(session, mechanism, baseKey, (ulong)expected.Length), "CKM_CONCATENATE_BASE_AND_KEY"));
            }
            finally
            {
                session.DestroyObject(second);
                session.DestroyObject(baseKey);
            }
        });
    }

    // CKM_CONCATENATE_BASE_AND_DATA, CKM_CONCATENATE_DATA_AND_BASE and CKM_XOR_BASE_AND_DATA take a
    // CK_KEY_DERIVATION_STRING_DATA (PKCS#11 v3.2). XOR gives as many bytes as the shorter of the
    // two.
    internal static void Assert_StringDataDerivation(IPkcs11Backend backend, CKM mechanism)
    {
        backend.RequireMechanisms(mechanism, CKM.CKM_SHA256_HMAC);
        byte[] expected = mechanism switch
        {
            CKM.CKM_CONCATENATE_BASE_AND_DATA => [.. BaseSecret, .. ShortData],
            CKM.CKM_CONCATENATE_DATA_AND_BASE => [.. ShortData, .. BaseSecret],
            CKM.CKM_XOR_BASE_AND_DATA => [.. BaseSecret.Zip(ShortData, (a, b) => (byte)(a ^ b))],
            _ => throw new ArgumentOutOfRangeException(nameof(mechanism)),
        };
        AssertDerivesFromGenericSecret(backend, BaseSecret, buffers => StringData(mechanism, buffers, ShortData), expected, $"{mechanism}");
    }

    // CKM_EXTRACT_KEY_FROM_KEY takes a CK_EXTRACT_PARAMS, the bit of the base key that is the derived key's first
    // bit, counting from the most significant bit of the first byte and wrapping around the end (PKCS#11
    // v3.2). The first row is the specification's own example: 0x329F84A9 from bit 21, two bytes, is 0x9526.
    public static TheoryData<string, int, int> Extractions => new()
    {
        { "329F84A9", 21, 2 },
        { "329F84A9", 0, 4 },
        { "329F84A9", 8, 4 },
        { "00112233445566778899AABBCCDDEEFF", 4, 8 },
    };

    internal static void Assert_ExtractKeyFromKey_StartsAtTheBitGiven(IPkcs11Backend backend, string baseHex, int bit, int length)
    {
        backend.RequireMechanisms(CKM.CKM_EXTRACT_KEY_FROM_KEY, CKM.CKM_SHA256_HMAC);
        byte[] baseValue = Convert.FromHexString(baseHex);
        int bits = baseValue.Length * 8;
        byte[] expected = new byte[length];
        for (int i = 0; i < length * 8; i++)
        {
            int source = (bit + i) % bits;
            if ((baseValue[source / 8] & (0x80 >> (source % 8))) != 0)
                expected[i / 8] |= (byte)(0x80 >> (i % 8));
        }
        if (bit == 21 && baseHex == "329F84A9")
            Assert.Equal([0x95, 0x26], expected); // the reference reproduces the specification's example
        AssertDerivesFromGenericSecret(backend, baseValue, _ => new Mechanism(CKM.CKM_EXTRACT_KEY_FROM_KEY, NativeULong((ulong)bit)),
            expected, $"CKM_EXTRACT_KEY_FROM_KEY from bit {bit}");
    }
}
