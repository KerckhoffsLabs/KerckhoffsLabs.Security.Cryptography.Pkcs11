using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These cases run hashes outside the default policy (MD2, MD5, SHA-1, RIPEMD, GOST, SHA-512/t) on purpose, under a
// scoped AllowInsecure lease; the compile-time policy analyzer flags them, so its warnings are suppressed for this
// file only.
#pragma warning disable KLPKCS11008, KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

// The digests, HMACs and general-length HMACs of every hash PKCS#11 names.
internal static partial class MechanismCoverageTestCases
{
    /// <summary>
    /// A hash and the mechanisms built on it. <see cref="Bcl"/> is the .NET runtime's implementation where it has
    /// one; where it has none, a case uses the token's own digest, which <see cref="Assert_Digest_KnownAnswer"/>
    /// checks against published vectors.
    /// </summary>
    internal sealed record HashFamily(
        string Name, CKM Digest, int BlockSize, int Size,
        CKM? Hmac, CKM? HmacGeneral, CKM? KeyDerivation, CKM? KeyGen, CKK? HmacKeyType,
        Func<byte[], byte[]>? Bcl);

    private static Func<byte[], byte[]>? IfSupported(bool supported, Func<byte[], byte[]> hash) => supported ? hash : null;

    internal static readonly HashFamily[] Families =
    [
        new("MD2", CKM.CKM_MD2, 16, 16, CKM.CKM_MD2_HMAC, CKM.CKM_MD2_HMAC_GENERAL, CKM.CKM_MD2_KEY_DERIVATION, null, null, null),
        new("MD5", CKM.CKM_MD5, 64, 16, CKM.CKM_MD5_HMAC, CKM.CKM_MD5_HMAC_GENERAL, CKM.CKM_MD5_KEY_DERIVATION, null, CKK.CKK_MD5_HMAC, MD5.HashData),
        new("SHA-1", CKM.CKM_SHA_1, 64, 20, CKM.CKM_SHA_1_HMAC, CKM.CKM_SHA_1_HMAC_GENERAL, CKM.CKM_SHA1_KEY_DERIVATION, CKM.CKM_SHA_1_KEY_GEN, CKK.CKK_SHA_1_HMAC, SHA1.HashData),
        new("SHA-224", CKM.CKM_SHA224, 64, 28, CKM.CKM_SHA224_HMAC, CKM.CKM_SHA224_HMAC_GENERAL, CKM.CKM_SHA224_KEY_DERIVATION, CKM.CKM_SHA224_KEY_GEN, CKK.CKK_SHA224_HMAC, null),
        new("SHA-256", CKM.CKM_SHA256, 64, 32, CKM.CKM_SHA256_HMAC, CKM.CKM_SHA256_HMAC_GENERAL, CKM.CKM_SHA256_KEY_DERIVATION, CKM.CKM_SHA256_KEY_GEN, CKK.CKK_SHA256_HMAC, SHA256.HashData),
        new("SHA-384", CKM.CKM_SHA384, 128, 48, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA384_HMAC_GENERAL, CKM.CKM_SHA384_KEY_DERIVATION, CKM.CKM_SHA384_KEY_GEN, CKK.CKK_SHA384_HMAC, SHA384.HashData),
        new("SHA-512", CKM.CKM_SHA512, 128, 64, CKM.CKM_SHA512_HMAC, CKM.CKM_SHA512_HMAC_GENERAL, CKM.CKM_SHA512_KEY_DERIVATION, CKM.CKM_SHA512_KEY_GEN, CKK.CKK_SHA512_HMAC, SHA512.HashData),
        new("SHA-512/224", CKM.CKM_SHA512_224, 128, 28, CKM.CKM_SHA512_224_HMAC, CKM.CKM_SHA512_224_HMAC_GENERAL, CKM.CKM_SHA512_224_KEY_DERIVATION, CKM.CKM_SHA512_224_KEY_GEN, CKK.CKK_SHA512_224_HMAC, null),
        new("SHA-512/256", CKM.CKM_SHA512_256, 128, 32, CKM.CKM_SHA512_256_HMAC, CKM.CKM_SHA512_256_HMAC_GENERAL, CKM.CKM_SHA512_256_KEY_DERIVATION, CKM.CKM_SHA512_256_KEY_GEN, CKK.CKK_SHA512_256_HMAC, null),
        new("SHA3-224", CKM.CKM_SHA3_224, 144, 28, CKM.CKM_SHA3_224_HMAC, CKM.CKM_SHA3_224_HMAC_GENERAL, CKM.CKM_SHA3_224_KEY_DERIVATION, CKM.CKM_SHA3_224_KEY_GEN, CKK.CKK_SHA3_224_HMAC, null),
        new("SHA3-256", CKM.CKM_SHA3_256, 136, 32, CKM.CKM_SHA3_256_HMAC, CKM.CKM_SHA3_256_HMAC_GENERAL, CKM.CKM_SHA3_256_KEY_DERIVATION, CKM.CKM_SHA3_256_KEY_GEN, CKK.CKK_SHA3_256_HMAC, IfSupported(SHA3_256.IsSupported, SHA3_256.HashData)),
        new("SHA3-384", CKM.CKM_SHA3_384, 104, 48, CKM.CKM_SHA3_384_HMAC, CKM.CKM_SHA3_384_HMAC_GENERAL, CKM.CKM_SHA3_384_KEY_DERIVATION, CKM.CKM_SHA3_384_KEY_GEN, CKK.CKK_SHA3_384_HMAC, IfSupported(SHA3_384.IsSupported, SHA3_384.HashData)),
        new("SHA3-512", CKM.CKM_SHA3_512, 72, 64, CKM.CKM_SHA3_512_HMAC, CKM.CKM_SHA3_512_HMAC_GENERAL, CKM.CKM_SHA3_512_KEY_DERIVATION, CKM.CKM_SHA3_512_KEY_GEN, CKK.CKK_SHA3_512_HMAC, IfSupported(SHA3_512.IsSupported, SHA3_512.HashData)),
        new("RIPEMD-128", CKM.CKM_RIPEMD128, 64, 16, CKM.CKM_RIPEMD128_HMAC, CKM.CKM_RIPEMD128_HMAC_GENERAL, null, null, CKK.CKK_RIPEMD128_HMAC, null),
        new("RIPEMD-160", CKM.CKM_RIPEMD160, 64, 20, CKM.CKM_RIPEMD160_HMAC, CKM.CKM_RIPEMD160_HMAC_GENERAL, null, null, CKK.CKK_RIPEMD160_HMAC, null),
        new("BLAKE2b-160", CKM.CKM_BLAKE2B_160, 128, 20, CKM.CKM_BLAKE2B_160_HMAC, CKM.CKM_BLAKE2B_160_HMAC_GENERAL, CKM.CKM_BLAKE2B_160_KEY_DERIVE, CKM.CKM_BLAKE2B_160_KEY_GEN, CKK.CKK_BLAKE2B_160_HMAC, null),
        new("BLAKE2b-256", CKM.CKM_BLAKE2B_256, 128, 32, CKM.CKM_BLAKE2B_256_HMAC, CKM.CKM_BLAKE2B_256_HMAC_GENERAL, CKM.CKM_BLAKE2B_256_KEY_DERIVE, CKM.CKM_BLAKE2B_256_KEY_GEN, CKK.CKK_BLAKE2B_256_HMAC, null),
        new("BLAKE2b-384", CKM.CKM_BLAKE2B_384, 128, 48, CKM.CKM_BLAKE2B_384_HMAC, CKM.CKM_BLAKE2B_384_HMAC_GENERAL, CKM.CKM_BLAKE2B_384_KEY_DERIVE, CKM.CKM_BLAKE2B_384_KEY_GEN, CKK.CKK_BLAKE2B_384_HMAC, null),
        new("BLAKE2b-512", CKM.CKM_BLAKE2B_512, 128, 64, CKM.CKM_BLAKE2B_512_HMAC, CKM.CKM_BLAKE2B_512_HMAC_GENERAL, CKM.CKM_BLAKE2B_512_KEY_DERIVE, CKM.CKM_BLAKE2B_512_KEY_GEN, CKK.CKK_BLAKE2B_512_HMAC, null),
        new("GOST R 34.11-94", CKM.CKM_GOSTR3411, 32, 32, CKM.CKM_GOSTR3411_HMAC, null, null, null, null, null),
    ];

    private static HashFamily Family(string name) => Families.Single(f => f.Name == name);

    private static TheoryData<string> FamiliesWhere(Func<HashFamily, bool> predicate) => [.. Families.Where(predicate).Select(f => f.Name)];

    public static TheoryData<string> HmacFamilies => FamiliesWhere(f => f.Hmac is not null);
    public static TheoryData<string> HmacGeneralFamilies => FamiliesWhere(f => f.HmacGeneral is not null);

    // The family's hash: the runtime's where it has one, otherwise the token's own digest.
    private static Func<byte[], byte[]> HashOf(Pkcs11SessionCore session, HashFamily family)
        => family.Bcl ?? (data => session.Digest(new Mechanism(family.Digest), data));

    // === Digests ================================================================

    /// <summary>
    /// Published vectors for the hashes the .NET runtime does not have: RFC 1319 §A.5 (MD2); the RIPEMD authors'
    /// (Dobbertin, Bosselaers, Preneel) for RIPEMD-128 and -160; RFC 7693 Appendix A and the BLAKE2 reference
    /// implementation for BLAKE2b; and GOST R 34.11-94 under the CryptoPro hash parameter set (RFC 4357 §11.2),
    /// which PKCS#11 v3.2 makes the default. None is empty: not every token digests empty data.
    /// </summary>
    public static TheoryData<CKM, string, string> DigestVectors => new()
    {
        { CKM.CKM_MD2, "abc", "da853b0d3f88d99b30283a69e6ded6bb" },
        { CKM.CKM_MD2, "message digest", "ab4f496bfb2a530b219ff33031fe06b0" },
        { CKM.CKM_RIPEMD128, "abc", "c14a12199c66e4ba84636b0f69144c77" },
        { CKM.CKM_RIPEMD128, "message digest", "9e327b3d6e523062afc1132d7df9d1b8" },
        { CKM.CKM_RIPEMD160, "abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
        { CKM.CKM_RIPEMD160, "message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36" },
        { CKM.CKM_BLAKE2B_160, "abc", "384264f676f39536840523f284921cdc68b6846b" },
        { CKM.CKM_BLAKE2B_160, "message digest", "6bfec6f65e52962be863d6ea1005fc5e4cc8478c" },
        { CKM.CKM_BLAKE2B_256, "abc", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319" },
        { CKM.CKM_BLAKE2B_256, "message digest", "31a65b562925c6ffefdafa0ad830f4e33eff148856c2b4754de273814adf8b85" },
        { CKM.CKM_BLAKE2B_384, "abc", "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4" },
        { CKM.CKM_BLAKE2B_384, "message digest", "44c3965bd8f02ed299ad52ffb5bba7c448df242073c5520dc091a0cc55d024cdd51569c339d0bf2b6cd746708683a0ef" },
        { CKM.CKM_BLAKE2B_512, "abc", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923" },
        { CKM.CKM_BLAKE2B_512, "message digest", "3c26ce487b1c0f062363afa3c675ebdbf5f4ef9bdc022cfbef91e3111cdc283840d8331fc30a8a0906cff4bcdbcd230c61aaec60fdfad457ed96b709a382359a" },
        { CKM.CKM_GOSTR3411, "abc", "b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c" },
        { CKM.CKM_GOSTR3411, "message digest", "bc6041dd2aa401ebfa6e9886734174febdb4729aa972d60f549ac39b29721ba0" },
    };

    internal static void Assert_Digest_KnownAnswer(IPkcs11Backend backend, CKM mechanism, string message, string expected)
    {
        backend.RequireMechanism(mechanism);
        WithSession(backend, session =>
            Assert.Equal(expected, Convert.ToHexStringLower(session.Digest(new Mechanism(mechanism), System.Text.Encoding.ASCII.GetBytes(message)))));
    }

    // CKM_GOSTR3411 takes an optional parameter, the DER OID of the hash parameter set (PKCS#11 v3.2).
    // Naming the default set, id-GostR3411-94-CryptoProParamSet (1.2.643.2.2.30.1), digests as no parameter does.
    internal static void Assert_Gost3411_WithTheDefaultParameterSet_DigestsAsWithout(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_GOSTR3411);
        byte[] cryptoProParamSet = [0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1E, 0x01];
        WithSession(backend, session =>
            Assert.Equal(session.Digest(new Mechanism(CKM.CKM_GOSTR3411), Abc),
                Taken(() => session.Digest(new Mechanism(CKM.CKM_GOSTR3411, cryptoProParamSet), Abc), "an explicit GOST R 34.11-94 parameter set")));
    }

    // CKM_SHA512_T takes t, the output length in bits, as a CK_MAC_GENERAL_PARAMS (PKCS#11 v3.2): with t
    // of 224 and 256 it is SHA-512/224 and SHA-512/256 (FIPS 180-4 §5.3.6, vectors from its examples).
    public static TheoryData<int, string> Sha512TVectors => new()
    {
        { 224, "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" },
        { 256, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" },
    };

    internal static void Assert_Sha512T_IsSha512TruncatedToT(IPkcs11Backend backend, int t, string expected)
    {
        backend.RequireMechanism(CKM.CKM_SHA512_T);
        WithSession(backend, session =>
            Assert.Equal(expected, Convert.ToHexStringLower(session.Digest(new Mechanism(CKM.CKM_SHA512_T, NativeULong((ulong)t)), Abc))));
    }

    // === HMAC ===================================================================

    // The HMAC of a message under a key equals RFC 2104 over the family's hash, and verifies; a changed MAC does not.
    internal static void Assert_Hmac_IsRfc2104OverTheHash(IPkcs11Backend backend, string familyName)
    {
        HashFamily family = Family(familyName);
        CKM hmac = family.Hmac!.Value;
        if (family.Bcl is null)
            backend.RequireMechanisms(hmac, family.Digest);
        else
            backend.RequireMechanism(hmac);
        byte[] key = [.. Enumerable.Range(0, family.Size).Select(i => (byte)(0x0B + i))];
        WithSession(backend, session =>
        {
            ObjectHandle handle = CreateSecret(session, CKK.CKK_GENERIC_SECRET, key, CKA.CKA_SIGN, CKA.CKA_VERIFY);
            try
            {
                byte[] expected = ReferenceHmac(HashOf(session, family), family.BlockSize, key, Message);
                byte[] mac = Taken(() => session.Sign(new Mechanism(hmac), handle, Message), $"{hmac} under a generic secret");
                Assert.Equal(expected, mac);
                Assert.True(session.Verify(new Mechanism(hmac), handle, Message, mac));
                mac[0] ^= 0x01;
                Assert.False(session.Verify(new Mechanism(hmac), handle, Message, mac));
            }
            finally { session.DestroyObject(handle); }
        });
    }

    // A general-length HMAC takes the MAC length in bytes as a CK_MAC_GENERAL_PARAMS and gives that many leading
    // bytes of the HMAC (PKCS#11 v3.2), from one byte to the whole of it; each verifies.
    internal static void Assert_HmacGeneral_IsTheLeadingBytesOfTheHmac(IPkcs11Backend backend, string familyName)
    {
        HashFamily family = Family(familyName);
        CKM general = family.HmacGeneral!.Value;
        if (family.Bcl is null)
            backend.RequireMechanisms(general, family.Digest);
        else
            backend.RequireMechanism(general);
        byte[] key = [.. Enumerable.Range(0, family.Size).Select(i => (byte)(0x20 + i))];
        WithSession(backend, session =>
        {
            ObjectHandle handle = CreateSecret(session, CKK.CKK_GENERIC_SECRET, key, CKA.CKA_SIGN, CKA.CKA_VERIFY);
            try
            {
                byte[] full = ReferenceHmac(HashOf(session, family), family.BlockSize, key, Message);
                foreach (int length in new[] { 1, family.Size / 2, family.Size }.Distinct())
                {
                    var mechanism = new Mechanism(general, NativeULong((ulong)length));
                    byte[] mac = Taken(() => session.Sign(mechanism, handle, Message), $"{general} with a {length}-byte MAC");
                    Assert.Equal(full[..length], mac);
                    Assert.True(session.Verify(mechanism, handle, Message, mac), $"{general}: a {length}-byte MAC does not verify.");
                    mac[^1] ^= 0x01;
                    Assert.False(session.Verify(mechanism, handle, Message, mac), $"{general}: a changed {length}-byte MAC verifies.");
                }
            }
            finally { session.DestroyObject(handle); }
        });
    }
}
