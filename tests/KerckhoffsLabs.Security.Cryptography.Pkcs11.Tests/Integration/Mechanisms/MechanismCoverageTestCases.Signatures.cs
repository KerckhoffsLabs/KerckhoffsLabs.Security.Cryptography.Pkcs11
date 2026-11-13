using System.Numerics;
using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These cases sign with mechanisms outside the default policy (PKCS#1 v1.5, MD2, MD5, SHA-1, RIPEMD, ISO/IEC 9796,
// ANSI X9.31) on purpose, under a scoped AllowInsecure lease; the compile-time policy analyzer flags them, so its
// warnings are suppressed for this file only.
#pragma warning disable KLPKCS11008, KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

// The hash-then-sign RSA and ECDSA mechanisms, ANSI X9.31 and ISO/IEC 9796 RSA, and signatures with message recovery.
internal static partial class MechanismCoverageTestCases
{
    private static readonly Lazy<RSA> SigningRsa = new(() => RSA.Create(2048));

    // Imports SigningRsa as a session key pair; the public key verifies (and recovers), the private key signs (and
    // signs with recovery).
    private static (ObjectHandle Public, ObjectHandle Private) ImportSigningRsa(Pkcs11SessionCore session)
        => TestKeys.ImportRsaRecoveryKeyPair(session, SigningRsa.Value, recover: true);

    // s^e mod n as k bytes: the encoded message inside an RSA signature.
    private static byte[] RsaOpen(RSA rsa, byte[] signature, int length)
    {
        RSAParameters p = rsa.ExportParameters(false);
        var n = new BigInteger(p.Modulus, isUnsigned: true, isBigEndian: true);
        var e = new BigInteger(p.Exponent, isUnsigned: true, isBigEndian: true);
        var s = new BigInteger(signature, isUnsigned: true, isBigEndian: true);
        return ToBytes(BigInteger.ModPow(s, e, n), length);
    }

    private static byte[] ToBytes(BigInteger value, int length)
    {
        byte[] raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] padded = new byte[length];
        raw.CopyTo(padded, length - raw.Length);
        return padded;
    }

    // === RSA PKCS#1 v1.5 ========================================================

    /// <summary>
    /// The DER DigestInfo prefix of each hash (RFC 8017 §9.2 note 1, with RIPEMD's OIDs from ISO/IEC 10118-3 via
    /// TeleTrusT and SHA3-224's from NIST CSOR), all with an explicit NULL parameter.
    /// </summary>
    private static readonly Dictionary<CKM, (string Family, string Prefix)> Pkcs1Signatures = new()
    {
        [CKM.CKM_MD2_RSA_PKCS] = ("MD2", "3020300c06082a864886f70d020205000410"),
        [CKM.CKM_MD5_RSA_PKCS] = ("MD5", "3020300c06082a864886f70d020505000410"),
        [CKM.CKM_SHA1_RSA_PKCS] = ("SHA-1", "3021300906052b0e03021a05000414"),
        [CKM.CKM_RIPEMD128_RSA_PKCS] = ("RIPEMD-128", "301d300906052b2403020205000410"),
        [CKM.CKM_RIPEMD160_RSA_PKCS] = ("RIPEMD-160", "3021300906052b2403020105000414"),
        [CKM.CKM_SHA224_RSA_PKCS] = ("SHA-224", "302d300d06096086480165030402040500041c"),
        [CKM.CKM_SHA3_224_RSA_PKCS] = ("SHA3-224", "302d300d06096086480165030402070500041c"),
    };

    public static TheoryData<CKM> Pkcs1SignatureMechanisms => [.. Pkcs1Signatures.Keys];

    // A hash-then-sign PKCS#1 v1.5 signature opens to 00 01 FF…FF 00 ‖ DigestInfo(hash of the message) (RFC 8017
    // §9.2), verifies on the token, and a changed signature does not (unless the backend's wrapper says the token
    // answers an altered signature with an error instead of false).
    internal static void Assert_RsaPkcs1Signature_IsEmsaPkcs1OverTheHash(IPkcs11Backend backend, CKM mechanism, bool rejectsAlteredSignatures = true)
    {
        (string familyName, string prefix) = Pkcs1Signatures[mechanism];
        HashFamily family = Family(familyName);
        if (family.Bcl is null)
            backend.RequireMechanisms(mechanism, family.Digest);
        else
            backend.RequireMechanism(mechanism);
        WithSession(backend, session =>
        {
            (ObjectHandle pub, ObjectHandle priv) = ImportSigningRsa(session);
            try
            {
                byte[] digestInfo = [.. Convert.FromHexString(prefix), .. HashOf(session, family)(Message)];
                byte[] expected = [0x00, 0x01, .. Enumerable.Repeat((byte)0xFF, 256 - 3 - digestInfo.Length), 0x00, .. digestInfo];
                byte[] signature = Taken(() => session.Sign(new Mechanism(mechanism), priv, Message), $"{mechanism}");
                Assert.Equal(Convert.ToHexStringLower(expected), Convert.ToHexStringLower(RsaOpen(SigningRsa.Value, signature, 256)));
                Assert.True(session.Verify(new Mechanism(mechanism), pub, Message, signature));
                if (!rejectsAlteredSignatures)
                    return;
                signature[^1] ^= 0x01;
                Assert.False(session.Verify(new Mechanism(mechanism), pub, Message, signature));
            }
            finally
            {
                session.DestroyObject(priv);
                session.DestroyObject(pub);
            }
        });
    }

    // === RSA-PSS ================================================================

    private static readonly Dictionary<CKM, (string Family, CKM Hash, CKG Mgf)> PssSignatures = new()
    {
        [CKM.CKM_SHA1_RSA_PKCS_PSS] = ("SHA-1", CKM.CKM_SHA_1, CKG.CKG_MGF1_SHA1),
        [CKM.CKM_SHA224_RSA_PKCS_PSS] = ("SHA-224", CKM.CKM_SHA224, CKG.CKG_MGF1_SHA224),
        [CKM.CKM_SHA3_224_RSA_PKCS_PSS] = ("SHA3-224", CKM.CKM_SHA3_224, CKG.CKG_MGF1_SHA3_224),
    };

    public static TheoryData<CKM> PssSignatureMechanisms => [.. PssSignatures.Keys];

    // A hash-then-sign PSS signature with a salt as long as the hash passes EMSA-PSS-VERIFY (RFC 8017 §9.1.2) over
    // the hash and MGF1 its parameters name, verifies on the token, and a changed signature does not.
    internal static void Assert_RsaPssSignature_PassesEmsaPssVerify(IPkcs11Backend backend, CKM mechanism)
    {
        (string familyName, CKM hashMechanism, CKG mgf) = PssSignatures[mechanism];
        HashFamily family = Family(familyName);
        if (family.Bcl is null)
            backend.RequireMechanisms(mechanism, family.Digest);
        else
            backend.RequireMechanism(mechanism);
        WithSession(backend, session =>
        {
            (ObjectHandle pub, ObjectHandle priv) = ImportSigningRsa(session);
            try
            {
                var pss = new Mechanism(mechanism, new CkmRsaPkcsPssParams(hashMechanism, mgf, family.Size));
                byte[] signature = Taken(() => session.Sign(pss, priv, Message), $"{mechanism} with a {family.Size}-byte salt");
                Func<byte[], byte[]> hash = HashOf(session, family);
                byte[] encoded = RsaOpen(SigningRsa.Value, signature, 256);
                Assert.True(EmsaPssVerify(hash, family.Size, hash(Message), encoded, 2047, family.Size),
                    $"A {mechanism} signature does not pass EMSA-PSS-VERIFY.");
                Assert.True(session.Verify(pss, pub, Message, signature));
                signature[^1] ^= 0x01;
                Assert.False(session.Verify(pss, pub, Message, signature));
            }
            finally
            {
                session.DestroyObject(priv);
                session.DestroyObject(pub);
            }
        });
    }

    // RFC 8017 §9.1.2 with MGF1 over the same hash.
    internal static bool EmsaPssVerify(Func<byte[], byte[]> hash, int hashLength, byte[] messageHash, byte[] encoded, int emBits, int saltLength)
    {
        int emLength = (emBits + 7) / 8;
        byte[] em = encoded[^emLength..];
        if (em[^1] != 0xBC)
            return false;
        int dbLength = emLength - hashLength - 1;
        byte[] maskedDb = em[..dbLength];
        byte[] h = em[dbLength..^1];
        byte topMask = (byte)(0xFF >> (8 * emLength - emBits));
        if ((maskedDb[0] & ~topMask) != 0)
            return false;
        byte[] db = [.. maskedDb.Zip(Mgf1(hash, h, dbLength), (a, b) => (byte)(a ^ b))];
        db[0] &= topMask;
        int separator = dbLength - saltLength - 1;
        if (db[..separator].Any(b => b != 0) || db[separator] != 0x01)
            return false;
        byte[] salt = db[(separator + 1)..];
        return hash([.. new byte[8], .. messageHash, .. salt]).AsSpan().SequenceEqual(h);
    }

    private static byte[] Mgf1(Func<byte[], byte[]> hash, byte[] seed, int length)
    {
        var mask = new List<byte>(length);
        for (uint counter = 0; mask.Count < length; counter++)
        {
            byte[] c = new byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(c, counter);
            mask.AddRange(hash([.. seed, .. c]));
        }
        return [.. mask.Take(length)];
    }

    // === ECDSA ==================================================================

    private static readonly byte[] P256Oid = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    private static readonly Dictionary<CKM, string> EcdsaSignatures = new()
    {
        [CKM.CKM_ECDSA_SHA1] = "SHA-1",
        [CKM.CKM_ECDSA_SHA224] = "SHA-224",
        [CKM.CKM_ECDSA_SHA256] = "SHA-256",
        [CKM.CKM_ECDSA_SHA384] = "SHA-384",
        [CKM.CKM_ECDSA_SHA512] = "SHA-512",
        [CKM.CKM_ECDSA_SHA3_224] = "SHA3-224",
        [CKM.CKM_ECDSA_SHA3_256] = "SHA3-256",
        [CKM.CKM_ECDSA_SHA3_384] = "SHA3-384",
        [CKM.CKM_ECDSA_SHA3_512] = "SHA3-512",
    };

    public static TheoryData<CKM> EcdsaSignatureMechanisms => [.. EcdsaSignatures.Keys];

    // A hash-then-sign ECDSA signature on P-256, r ‖ s, verifies under the runtime's ECDSA over the hash of the
    // message (FIPS 186-5 §6.4.2, which takes the hash's leading bits when it is longer than the order), and on the
    // token; a changed signature does not.
    internal static void Assert_EcdsaSignature_VerifiesOverTheHash(IPkcs11Backend backend, CKM mechanism)
    {
        HashFamily family = Family(EcdsaSignatures[mechanism]);
        if (family.Bcl is null)
            backend.RequireMechanisms(mechanism, family.Digest);
        else
            backend.RequireMechanism(mechanism);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters key = ecdsa.ExportParameters(true);
        WithSession(backend, session =>
        {
            using var privateTemplate = new Template(
            [
                new(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_EC), new(CKA.CKA_TOKEN, false),
                new(CKA.CKA_SIGN, true), new(CKA.CKA_EC_PARAMS, P256Oid), new(CKA.CKA_VALUE, key.D!),
            ]);
            ObjectHandle priv = session.CreateObject(privateTemplate.Attributes);
            ObjectHandle pub = TestKeys.ImportEcP256PublicKey(session, key.Q.X!, key.Q.Y!);
            try
            {
                byte[] signature = Taken(() => session.Sign(new Mechanism(mechanism), priv, Message), $"{mechanism}");
                Assert.Equal(64, signature.Length);
                Assert.True(ecdsa.VerifyHash(HashOf(session, family)(Message), signature), $"A {mechanism} signature does not verify over the hash.");
                Assert.True(session.Verify(new Mechanism(mechanism), pub, Message, signature));
                signature[^1] ^= 0x01;
                Assert.False(session.Verify(new Mechanism(mechanism), pub, Message, signature));
            }
            finally
            {
                session.DestroyObject(pub);
                session.DestroyObject(priv);
            }
        });
    }

    // === ANSI X9.31 =============================================================

    // CKM_RSA_X9_31_KEY_PAIR_GEN makes a key pair of the modulus length and exponent asked for, and its
    // CKM_SHA1_RSA_X9_31 signature is min(σ, n − σ) for σ the RSA of 6B BB…BB BA ‖ SHA-1(message) ‖ 33 CC (ANSI X9.31
    // §4.2 and §6.3, PKCS#11 v3.2); it verifies on the token, and a changed signature does not.
    internal static void Assert_RsaX931_KeyPairSignsAsX931Says(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_X9_31_KEY_PAIR_GEN, CKM.CKM_SHA1_RSA_X9_31);
        WithSession(backend, session =>
        {
            using var publicTemplate = new Template(
            [
                new(CKA.CKA_TOKEN, false), new(CKA.CKA_VERIFY, true), new(CKA.CKA_MODULUS_BITS, 2048UL),
                new(CKA.CKA_PUBLIC_EXPONENT, [0x01, 0x00, 0x01]),
            ]);
            using var privateTemplate = new Template([new(CKA.CKA_TOKEN, false), new(CKA.CKA_SIGN, true)]);
            ObjectHandle pub = default, priv = default;
            Taken(() =>
            {
                session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_X9_31_KEY_PAIR_GEN), publicTemplate.Attributes, privateTemplate.Attributes, out pub, out priv);
                return 0;
            }, "CKM_RSA_X9_31_KEY_PAIR_GEN for a 2048-bit key");
            try
            {
                byte[] modulus = ReadAttribute(session, pub, CKA.CKA_MODULUS);
                Assert.Equal(256, modulus.Length);
                Assert.Equal([0x01, 0x00, 0x01], ReadAttribute(session, pub, CKA.CKA_PUBLIC_EXPONENT).SkipWhile(b => b == 0));
                Assert.Equal((ulong)CKM.CKM_RSA_X9_31_KEY_PAIR_GEN, ReadULong(session, pub, CKA.CKA_KEY_GEN_MECHANISM));

                var mechanism = new Mechanism(CKM.CKM_SHA1_RSA_X9_31);
                byte[] signature = session.Sign(mechanism, priv, Message);
                var n = new BigInteger(modulus, isUnsigned: true, isBigEndian: true);
                var t = BigInteger.ModPow(new BigInteger(signature, isUnsigned: true, isBigEndian: true), 65537, n);
                if ((t & 0x0F) != 12)
                    t = n - t;
                // 6B, then BB up to BA, then the hash and the two-byte SHA-1 trailer, 256 bytes in all.
                byte[] expected = [0x6B, .. Enumerable.Repeat((byte)0xBB, 256 - 1 - 1 - 20 - 2), 0xBA, .. SHA1.HashData(Message), 0x33, 0xCC];
                Assert.Equal(256, expected.Length);
                Assert.Equal(Convert.ToHexStringLower(expected), Convert.ToHexStringLower(ToBytes(t, 256)));
                Assert.True(session.Verify(mechanism, pub, Message, signature));
                signature[^1] ^= 0x01;
                Assert.False(session.Verify(mechanism, pub, Message, signature));
            }
            finally
            {
                session.DestroyObject(priv);
                session.DestroyObject(pub);
            }
        });
    }

    // === Signatures with message recovery =======================================

    // CKM_RSA_9796 (ISO/IEC 9796-1) signs data of up to half the modulus; C_Verify takes the
    // signature, C_VerifyRecover gives the data back, and C_SignRecover gives the same signature as C_Sign (the
    // scheme is deterministic). C_SignRecover has no wrapper yet, so this calls the low-level binding.
    internal static void Assert_Rsa9796_SignsWithMessageRecovery(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_RSA_9796);
        byte[] data = [.. Enumerable.Range(0, 32).Select(i => (byte)(0x41 + i))];
        WithSession(backend, session =>
        {
            (ObjectHandle pub, ObjectHandle priv) = ImportSigningRsa(session);
            try
            {
                var mechanism = new Mechanism(CKM.CKM_RSA_9796);
                byte[] signature = Taken(() => session.Sign(mechanism, priv, data), "CKM_RSA_9796");
                Assert.Equal(256, signature.Length);
                Assert.True(session.Verify(mechanism, pub, data, signature));
                Assert.True(session.VerifyRecover(mechanism, pub, signature, out byte[] recovered));
                Assert.Equal(data, recovered);
                Assert.Equal(signature, SignRecover(backend, session, mechanism, priv, data));
            }
            finally
            {
                session.DestroyObject(priv);
                session.DestroyObject(pub);
            }
        });
    }

    // CKM_RSA_PKCS with recovery: C_SignRecover over a SHA-256 DigestInfo is the runtime's PKCS#1 v1.5 SHA-256
    // signature, and C_VerifyRecover gives the DigestInfo back.
    internal static void Assert_RsaPkcs_SignRecover_IsThePkcs1Signature(IPkcs11Backend backend)
    {
        backend.RequireMechanismFlags(CKM.CKM_RSA_PKCS, f => f.SignRecover, "C_SignRecover");
        byte[] digestInfo = TestKeys.Sha256DigestInfo(Message);
        WithSession(backend, session =>
        {
            (ObjectHandle pub, ObjectHandle priv) = ImportSigningRsa(session);
            try
            {
                var mechanism = new Mechanism(CKM.CKM_RSA_PKCS);
                byte[] signature = SignRecover(backend, session, mechanism, priv, digestInfo);
                Assert.Equal(SigningRsa.Value.SignData(Message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), signature);
                Assert.True(session.VerifyRecover(mechanism, pub, signature, out byte[] recovered));
                Assert.Equal(digestInfo, recovered);
            }
            finally
            {
                session.DestroyObject(priv);
                session.DestroyObject(pub);
            }
        });
    }

    // C_SignRecoverInit then C_SignRecover with a length query first, through the low-level binding.
    private static byte[] SignRecover(IPkcs11Backend backend, Pkcs11SessionCore session, Mechanism mechanism, ObjectHandle key, byte[] data)
    {
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        var sid = (NativeCULong)session.SessionId;
        using var scope = new MechanismParameterScope();
        CK_MECHANISM ck = mechanism.Marshal(scope, out _);
        Assert.Equal(CKR.CKR_OK, lowLevel.C_SignRecoverInit(sid, in ck, (NativeCULong)key.ObjectId));
        Assert.Equal(CKR.CKR_OK, lowLevel.C_SignRecover(sid, data, default, lengthOnly: true, out NativeCULong length));
        byte[] signature = new byte[(int)(ulong)length];
        Assert.Equal(CKR.CKR_OK, lowLevel.C_SignRecover(sid, data, signature, lengthOnly: false, out length));
        return signature[..(int)(ulong)length];
    }
}
