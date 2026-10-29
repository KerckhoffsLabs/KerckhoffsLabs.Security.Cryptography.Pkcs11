using System.Numerics;
using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// The OAEP key-transport case compares two AES keys by what CKM_AES_CBC makes of one block under each, and the
// PKCS#1 v1.5 case checks that mechanism's length bound. The compile-time policy analyzer flags both, so its
// warnings are suppressed for this file only.
#pragma warning disable KLPKCS11008, KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>
/// What the algorithms compute, checked on every real backend against a reference the test holds: the RSA-PSS
/// salt and mask the token was asked for, read back out of its signatures; RSA-OAEP's randomisation, key
/// transport and wrapped-key length; the PKCS#1 v1.5 length bound; raw RSA verification; the RFC 8032 EdDSA
/// variants other than pure Ed25519; ECDSA on the curves the rest of the suite does not reach; the 224-bit
/// digests; <c>C_DigestKey</c>; key agreement with a KDF, with the cofactor and on X448; HKDF with SHA-512 and
/// with a salt key; SHA-256 key derivation; AES key wrap's IV and integrity check; ML-KEM and HashML-DSA under
/// the wrong key or hash; and a saved digest state, with the refusals of saving and restoring one.
/// </summary>
/// <remarks>
/// <para>
/// A derived secret is compared through an HMAC under it rather than by reading it, so a module that derives
/// only sensitive keys (NSS) runs the same case. The vectors are RFC 8032 §7.2–7.5, RFC 7748 §6.2, FIPS 180-4 and
/// FIPS 202; a computed reference comes from the .NET runtime.
/// </para>
/// <para>
/// Every object is a session object, destroyed by the case. A case that needs a curve, mechanism or parameter the
/// module does not take skips; where a backend answers differently from PKCS#11, its wrapper says so.
/// </para>
/// </remarks>
internal static class AlgorithmConformanceTestCases
{
    private static readonly byte[] Message = "the quick brown fox jumps over the lazy dog"u8.ToArray();
    private static readonly byte[] Iv = [.. Enumerable.Range(1, 16).Select(i => (byte)i)];

    // A module's answers when it does not take a curve, key type or parameter it was given.
    private static readonly CKR[] NotTaken =
    [
        CKR.CKR_CURVE_NOT_SUPPORTED, CKR.CKR_DOMAIN_PARAMS_INVALID, CKR.CKR_ATTRIBUTE_VALUE_INVALID,
        CKR.CKR_TEMPLATE_INCONSISTENT, CKR.CKR_MECHANISM_PARAM_INVALID, CKR.CKR_MECHANISM_INVALID,
        CKR.CKR_KEY_TYPE_INCONSISTENT,
    ];

    private static void WithSession(IPkcs11Backend backend, Action<Pkcs11SessionCore> body)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try { body(session); }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // Runs create, and skips the case when the module refuses what it was given as something it does not take.
    private static T OrSkip<T>(Func<T> create, string what)
    {
        try { return create(); }
        catch (Pkcs11Exception ex) when (NotTaken.Contains(ex.ReturnValue))
        {
            Assert.Skip($"The backend does not take {what} ({ex.ReturnValue}).");
            throw;
        }
    }

    // A template that disposes its attributes with it.
    private sealed class Template(List<ObjectAttribute> attributes) : IDisposable
    {
        public List<ObjectAttribute> Attributes => attributes;

        public void Dispose()
        {
            foreach (ObjectAttribute attribute in attributes)
                attribute.Dispose();
        }
    }

    private static ObjectHandle CreateSecret(Pkcs11SessionCore session, CKK keyType, byte[] value, params CKA[] usages)
    {
        using var template = new Template(
        [
            new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), new(CKA.CKA_KEY_TYPE, keyType),
            new(CKA.CKA_TOKEN, false), new(CKA.CKA_VALUE, value),
            .. usages.Select(u => new ObjectAttribute(u, true)),
        ]);
        return session.CreateObject(template.Attributes);
    }

    // A generic secret of the length asked, which can only MAC: the case compares it through an HMAC under it.
    private static Template MacSecretTemplate(ulong length) => new(
    [
        new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET),
        new(CKA.CKA_TOKEN, false), new(CKA.CKA_VALUE_LEN, length), new(CKA.CKA_SIGN, true),
    ]);

    private static byte[] HmacOfDerived(Pkcs11SessionCore session, Mechanism mechanism, ObjectHandle baseKey, ulong length)
    {
        ObjectHandle derived;
        using (Template template = MacSecretTemplate(length))
            derived = session.DeriveKey(mechanism, baseKey, template.Attributes);
        try { return session.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), derived, Message); }
        finally { session.DestroyObject(derived); }
    }

    private static byte[] ReadAttribute(Pkcs11SessionCore session, ObjectHandle handle, CKA attribute)
    {
        using var read = session.GetAttributeValue(handle, [attribute]);
        return read[0].GetValueAsByteArray();
    }

    // === RSA-PSS ================================================================

    private static readonly (int Salt, CKG Mgf)[] PssSaltsAndMasks =
        [(0, CKG.CKG_MGF1_SHA256), (20, CKG.CKG_MGF1_SHA256), (32, CKG.CKG_MGF1_SHA256), (32, CKG.CKG_MGF1_SHA1)];

    // A CKM_SHA256_RSA_PKCS_PSS signature carries the salt length and mask generation function its parameters
    // name (RFC 8017 §9.1): decoding it with the public key gives a salt of that length under that MGF, and the
    // token verifies it under those parameters and no others (a module may refuse the others at C_VerifyInit
    // instead). One key pair for all of them. ignoresPssParameters records a module that ignores ulSaltLen and mgf:
    // it signs with a hash-length salt and MGF1 over the message hash, and verifies under any salt or MGF.
    internal static void Assert_RsaPss_SignatureCarriesTheSaltAndMaskAsked(IPkcs11Backend backend, bool ignoresPssParameters = false)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS_PSS);
        WithSession(backend, session =>
        {
            // A salt other than the hash length is outside the default policy.
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            var (pub, priv) = TestKeys.GenerateRsa2048SigningKeyPair(session);
            try
            {
                byte[] n = ReadAttribute(session, pub, CKA.CKA_MODULUS);
                byte[] e = ReadAttribute(session, pub, CKA.CKA_PUBLIC_EXPONENT);
                foreach ((int salt, CKG mgf) in PssSaltsAndMasks)
                {
                    byte[] signature;
                    try { signature = session.Sign(Pss(salt, mgf), priv, Message); }
                    catch (Pkcs11Exception ex) when (mgf != CKG.CKG_MGF1_SHA256 && ex.ReturnValue is CKR.CKR_MECHANISM_PARAM_INVALID or CKR.CKR_ARGUMENTS_BAD)
                    {
                        continue; // A module may tie the MGF hash to the message hash.
                    }

                    CKG otherMgf = mgf == CKG.CKG_MGF1_SHA1 ? CKG.CKG_MGF1_SHA256 : CKG.CKG_MGF1_SHA1;
                    Assert.True(Verifies(session, Pss(salt, mgf), pub, signature), $"salt {salt}, {mgf}: the signature should verify under its own parameters");
                    if (ignoresPssParameters)
                    {
                        Assert.Equal(32, RecoverPssSaltLength(signature, n, e, Message, CKG.CKG_MGF1_SHA256));
                        Assert.True(Verifies(session, Pss(salt + 1, mgf), pub, signature));
                        Assert.True(Verifies(session, Pss(salt, otherMgf), pub, signature));
                        continue;
                    }
                    Assert.Equal(salt, RecoverPssSaltLength(signature, n, e, Message, mgf));
                    Assert.False(Verifies(session, Pss(salt + 1, mgf), pub, signature), $"salt {salt}, {mgf}: it should not verify under a {salt + 1}-byte salt");
                    Assert.False(Verifies(session, Pss(salt, otherMgf), pub, signature), $"salt {salt}, {mgf}: it should not verify under {otherMgf}");
                }
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        });
    }

    // The salt can be as long as emLen - hLen - 2 and no longer (RFC 8017 §9.1.1 step 3): 222 bytes for a 2048-bit
    // key and SHA-256 signs and decodes to 222, and 223 is refused. ignoresPssParameters records a module that
    // ignores ulSaltLen: both sign, with a 32-byte salt.
    internal static void Assert_RsaPss_SaltLength_IsBoundedByTheModulus(IPkcs11Backend backend, bool ignoresPssParameters = false)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_SHA256_RSA_PKCS_PSS);
        WithSession(backend, session =>
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            var (pub, priv) = TestKeys.GenerateRsa2048SigningKeyPair(session);
            try
            {
                byte[] n = ReadAttribute(session, pub, CKA.CKA_MODULUS);
                byte[] e = ReadAttribute(session, pub, CKA.CKA_PUBLIC_EXPONENT);
                byte[] longest = session.Sign(Pss(222, CKG.CKG_MGF1_SHA256), priv, Message);
                if (ignoresPssParameters)
                {
                    Assert.Equal(32, RecoverPssSaltLength(longest, n, e, Message, CKG.CKG_MGF1_SHA256));
                    Assert.Equal(32, RecoverPssSaltLength(session.Sign(Pss(223, CKG.CKG_MGF1_SHA256), priv, Message), n, e, Message, CKG.CKG_MGF1_SHA256));
                    return;
                }
                Assert.Equal(222, RecoverPssSaltLength(longest, n, e, Message, CKG.CKG_MGF1_SHA256));
                Assert.True(session.Verify(Pss(222, CKG.CKG_MGF1_SHA256), pub, Message, longest));

                Assert.ThrowsAny<Pkcs11Exception>(() => session.Sign(Pss(223, CKG.CKG_MGF1_SHA256), priv, Message));
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        });
    }

    private static Mechanism Pss(int salt, CKG mgf) =>
        new(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, mgf, salt));

    // Whether the token verifies the signature under the mechanism; a refusal of the parameters is a no.
    private static bool Verifies(Pkcs11SessionCore session, Mechanism mechanism, ObjectHandle pub, byte[] signature)
    {
        try { return session.Verify(mechanism, pub, Message, signature); }
        catch (Pkcs11Exception ex) when (ex.ReturnValue is CKR.CKR_MECHANISM_PARAM_INVALID or CKR.CKR_ARGUMENTS_BAD) { return false; }
    }

    // EMSA-PSS-VERIFY (RFC 8017 §9.1.2) for SHA-256, with the salt length left open: returns the length of the
    // salt the encoded message carries, after checking that the hash over it matches.
    private static int RecoverPssSaltLength(byte[] signature, byte[] modulus, byte[] exponent, byte[] message, CKG mgf)
    {
        var n = new BigInteger(modulus, isUnsigned: true, isBigEndian: true);
        var s = new BigInteger(signature, isUnsigned: true, isBigEndian: true);
        long emBits = n.GetBitLength() - 1;
        int emLen = (int)((emBits + 7) / 8);
        byte[] m = BigInteger.ModPow(s, new BigInteger(exponent, isUnsigned: true, isBigEndian: true), n).ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] em = new byte[emLen];
        m.CopyTo(em, emLen - m.Length);
        Assert.Equal(0xBC, em[^1]);

        const int hLen = 32;
        byte[] h = em[(emLen - hLen - 1)..(emLen - 1)];
        byte[] db = em[..(emLen - hLen - 1)];
        byte[] mask = Mgf1(h, db.Length, mgf == CKG.CKG_MGF1_SHA1 ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256);
        for (int i = 0; i < db.Length; i++)
            db[i] ^= mask[i];
        db[0] &= (byte)(0xFF >> (int)(8 * emLen - emBits));

        int separator = Array.FindIndex(db, b => b != 0);
        Assert.True(separator >= 0 && db[separator] == 0x01, "the decoded DB should be zero padding, then 0x01, then the salt");
        byte[] salt = db[(separator + 1)..];
        Assert.Equal(SHA256.HashData([.. new byte[8], .. SHA256.HashData(message), .. salt]), h);
        return salt.Length;
    }

    private static byte[] Mgf1(byte[] seed, int length, HashAlgorithmName hash)
    {
        var output = new List<byte>(length);
        for (uint counter = 0; output.Count < length; counter++)
        {
            byte[] c = [(byte)(counter >> 24), (byte)(counter >> 16), (byte)(counter >> 8), (byte)counter];
            output.AddRange(CryptographicOperations.HashData(hash, [.. seed, .. c]));
        }
        return [.. output.Take(length)];
    }

    // === RSA-OAEP and PKCS#1 v1.5 ===============================================

    private static Mechanism OaepSha256 => new(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256));

    // OAEP is randomised (RFC 8017 §7.1.1): the same plaintext encrypts to two different ciphertexts, both of
    // which decrypt to it.
    internal static void Assert_RsaOaep_IsRandomised(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_PKCS_OAEP);
        WithSession(backend, session =>
        {
            var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
            try
            {
                byte[] first = OrSkip(() => session.Encrypt(OaepSha256, pub, Message), "OAEP with SHA-256");
                byte[] second = session.Encrypt(OaepSha256, pub, Message);
                Assert.NotEqual(first, second);
                Assert.Equal(Message, session.Decrypt(OaepSha256, priv, first));
                Assert.Equal(Message, session.Decrypt(OaepSha256, priv, second));
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        });
    }

    // An AES key wrapped under RSA-OAEP is a k-byte blob that unwraps to a key encrypting as the original does.
    // wrapRefused records a module that does not wrap under OAEP, with the code it gives.
    internal static void Assert_RsaOaep_TransportsAnAesKey(IPkcs11Backend backend, CKR? wrapRefused = null)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_PKCS_OAEP, CKM.CKM_AES_CBC);
        WithSession(backend, session =>
        {
            var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
            ObjectHandle original = TestKeys.ImportExtractableAesKey(session, [.. Enumerable.Range(0, 32).Select(i => (byte)(i * 7))]);
            try
            {
                if (wrapRefused is CKR refusal)
                {
                    var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.WrapKey(OaepSha256, pub, original));
                    Assert.Equal(refusal, ex.ReturnValue);
                    return;
                }
                byte[] wrapped = OrSkip(() => session.WrapKey(OaepSha256, pub, original), "OAEP with SHA-256");
                Assert.Equal(256, wrapped.Length);
                ObjectHandle copy;
                using (Template template = UnwrappedAesTemplate())
                    copy = session.UnwrapKey(OaepSha256, priv, wrapped, template.Attributes);
                try
                {
                    using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
                    var cbc = new Mechanism(CKM.CKM_AES_CBC, Iv);
                    Assert.Equal(session.Encrypt(cbc, original, new byte[16]), session.Encrypt(cbc, copy, new byte[16]));
                }
                finally { session.DestroyObject(copy); }
            }
            finally { session.DestroyObject(original); session.DestroyObject(priv); session.DestroyObject(pub); }
        });
    }

    // An RSA-OAEP ciphertext is exactly k bytes (RFC 8017 §7.1.2 step 1b): a blob one byte short of a 2048-bit
    // modulus, or one byte over, is invalid by its length alone, and C_UnwrapKey refuses it with
    // CKR_WRAPPED_KEY_LEN_RANGE (PKCS#11 v3.2 §5.1.6, §5.18.4) and creates no key. The k-byte blob then unwraps.
    internal static void Assert_RsaOaep_UnwrapOfABlobNotKBytes_IsWrappedKeyLenRange(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_PKCS_OAEP);
        backend.RequireMechanismFlags(CKM.CKM_RSA_PKCS_OAEP, f => f.Unwrap, "CKF_UNWRAP");
        WithSession(backend, session =>
        {
            var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
            try
            {
                byte[] wrapped = OrSkip(() => session.Encrypt(OaepSha256, pub, Target), "OAEP with SHA-256");
                Assert.Equal(256, wrapped.Length);
                using Template template = UnwrappedAesTemplate();
                foreach (byte[] bad in (byte[][])[wrapped[..^1], [.. wrapped, 0x00]])
                {
                    var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.UnwrapKey(OaepSha256, priv, bad, template.Attributes));
                    Assert.True(ex.ReturnValue == CKR.CKR_WRAPPED_KEY_LEN_RANGE,
                        $"C_UnwrapKey of a {bad.Length}-byte RSA-OAEP blob under a 2048-bit key returned {ex.ReturnValue}.");
                }
                session.DestroyObject(session.UnwrapKey(OaepSha256, priv, wrapped, template.Attributes));
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        });
    }

    // CKM_RSA_PKCS encrypts at most k - 11 bytes (RFC 8017 §7.2.1): 245 for a 2048-bit key round-trips, 246 is
    // refused.
    internal static void Assert_RsaPkcs1_Plaintext_IsBoundedByKMinus11(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_PKCS);
        WithSession(backend, session =>
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
            try
            {
                var pkcs1 = new Mechanism(CKM.CKM_RSA_PKCS);
                byte[] longest = [.. Enumerable.Range(0, 245).Select(i => (byte)(i + 1))];
                Assert.Equal(longest, session.Decrypt(pkcs1, priv, session.Encrypt(pkcs1, pub, longest)));

                Assert.ThrowsAny<Pkcs11Exception>(() => session.Encrypt(pkcs1, pub, [.. longest, 0x42]));
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        });
    }

    // === Raw RSA ================================================================

    // A 2048-bit signing key pair for CKM_RSA_X_509, on the token when asked: the lock a module takes on a token
    // key is the one an early return can leave held.
    private static (ObjectHandle Pub, ObjectHandle Priv) GenerateRawRsaPair(Pkcs11SessionCore session, bool onToken)
    {
        using var template = new Template(
        [
            new(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_RSA), new(CKA.CKA_TOKEN, onToken),
            new(CKA.CKA_VERIFY, true), new(CKA.CKA_MODULUS_BITS, 2048UL), new(CKA.CKA_PUBLIC_EXPONENT, (byte[])[0x01, 0x00, 0x01]),
        ]);
        using var privTemplate = new Template(
        [
            new(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_RSA), new(CKA.CKA_TOKEN, onToken),
            new(CKA.CKA_SENSITIVE, true), new(CKA.CKA_SIGN, true),
        ]);
        session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), template.Attributes, privTemplate.Attributes, out var pub, out var priv);
        return (pub, priv);
    }

    // A full 256-byte block whose top byte is not zero and below every 2048-bit modulus's (0x80 and up).
    private static byte[] RawRsaBlock()
    {
        byte[] m = RandomNumberGenerator.GetBytes(256);
        m[0] = 0x01;
        return m;
    }

    private static CKR RawRsa(Func<NativeCULong, CK_MECHANISM, CKR> call, NativeCULong key)
    {
        using var scope = new MechanismParameterScope();
        CK_MECHANISM mech = new Mechanism(CKM.CKM_RSA_X_509).Marshal(scope, out _);
        return call(key, mech);
    }

    private static byte[] RawRsaSign(LowLevelPkcs11Library lowLevel, NativeCULong sid, ObjectHandle priv, byte[] m)
    {
        Assert.Equal(CKR.CKR_OK, RawRsa((k, mech) => lowLevel.C_SignInit(sid, in mech, k), (NativeCULong)priv.ObjectId));
        byte[] signature = new byte[256];
        Assert.Equal(CKR.CKR_OK, lowLevel.C_Sign(sid, m, signature, lengthOnly: false, out NativeCULong length));
        Assert.Equal(256UL, (ulong)length);
        return signature;
    }

    private static CKR RawRsaVerify(LowLevelPkcs11Library lowLevel, NativeCULong sid, ObjectHandle pub, ReadOnlySpan<byte> data, byte[] signature)
    {
        Assert.Equal(CKR.CKR_OK, RawRsa((k, mech) => lowLevel.C_VerifyInit(sid, in mech, k), (NativeCULong)pub.ObjectId));
        return lowLevel.C_Verify(sid, data, signature);
    }

    private static void WithRawRsa(IPkcs11Backend backend, bool onToken, Action<LowLevelPkcs11Library, NativeCULong, ObjectHandle, ObjectHandle> body)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_X_509);
        backend.RequireMechanismFlags(CKM.CKM_RSA_X_509, f => f.Sign && f.Verify, "CKF_SIGN and CKF_VERIFY");
        WithSession(backend, session =>
        {
            var (pub, priv) = GenerateRawRsaPair(session, onToken);
            try { body(backend.Library.LowLevelLibrary!, (NativeCULong)session.SessionId, pub, priv); }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        });
    }

    // Raw RSA compares the zero-padded data with the whole k-byte block the signature recovers (§6.1.12: the
    // input is converted to an integer, so its leading zero bytes are the only ones it may leave out). A
    // signature over a block m whose top byte is not zero therefore verifies m, and does not verify m[1..]: a
    // module that compares only the trailing bytes accepts it for data it does not sign (CKR_SIGNATURE_INVALID,
    // §5.15.2). Through the raw dispatch: raw RSA is outside the library's policy.
    internal static void Assert_RsaX509_Verify_RequiresTheLeadingBytes(IPkcs11Backend backend) =>
        WithRawRsa(backend, onToken: false, (lowLevel, sid, pub, priv) =>
        {
            byte[] m = RawRsaBlock();
            byte[] signature = RawRsaSign(lowLevel, sid, priv, m);
            Assert.Equal(CKR.CKR_OK, RawRsaVerify(lowLevel, sid, pub, m, signature));
            CKR rv = RawRsaVerify(lowLevel, sid, pub, m.AsSpan(1), signature);
            Assert.True(rv == CKR.CKR_SIGNATURE_INVALID, $"C_Verify(CKM_RSA_X_509) of m[1..] under a signature over m returned {rv}.");
        });

    // C_Verify with CKM_RSA_X_509 takes at most k bytes of data (§6.1.12, Table 45): 257 bytes under a 2048-bit
    // token key are refused, with CKR_DATA_LEN_RANGE, or CKR_SIGNATURE_INVALID from a module that checks the
    // signature against the data as given, and the refusal ends the operation (§5.15.2). The token key then
    // verifies the right data at once: a module that kept the key locked on the error would hang or refuse it.
    internal static void Assert_RsaX509_Verify_OfDataLongerThanTheModulus_IsRefused(IPkcs11Backend backend) =>
        WithRawRsa(backend, onToken: true, (lowLevel, sid, pub, priv) =>
        {
            byte[] m = RawRsaBlock();
            byte[] signature = RawRsaSign(lowLevel, sid, priv, m);
            CKR rv = RawRsaVerify(lowLevel, sid, pub, [.. m, 0x00], signature);
            Assert.True(rv is CKR.CKR_DATA_LEN_RANGE or CKR.CKR_SIGNATURE_INVALID,
                $"C_Verify(CKM_RSA_X_509) of 257 bytes under a 2048-bit key returned {rv}.");
            Assert.Equal(CKR.CKR_OK, RawRsaVerify(lowLevel, sid, pub, m, signature));
            Assert.Equal(signature, RawRsaSign(lowLevel, sid, priv, m));
        });

    // === EdDSA ==================================================================

    public static TheoryData<string> EdDsaVariants => ["Ed25519ctx", "Ed25519ph", "Ed448", "Ed448ph"];

    private sealed record EdDsaVector(byte[] Oid, string Secret, string Public, string Message, string Signature, CkmEddsaParams Parameters);

    // RFC 8032 §7.2 (Ed25519ctx, context "foo"), §7.3 (Ed25519ph, "abc"), §7.4 (Ed448, the 1-octet message) and
    // §7.5 (Ed448ph, "abc").
    private static EdDsaVector EdDsaVectorFor(string variant) => variant switch
    {
        "Ed25519ctx" => new([0x06, 0x03, 0x2B, 0x65, 0x70],
            "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6",
            "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292",
            "f726936d19c800494e3fdaff20b276a8",
            "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d",
            new CkmEddsaParams(phFlag: false, "foo"u8)),
        "Ed25519ph" => new([0x06, 0x03, 0x2B, 0x65, 0x70],
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "616263",
            "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
            new CkmEddsaParams(phFlag: true)),
        "Ed448" => new([0x06, 0x03, 0x2B, 0x65, 0x71],
            "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
            "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
            "03",
            "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00",
            // Ed448 has no parameter-less form (PKCS#11 v3.2 §6.3.15): pure Ed448 is phFlag false, no context.
            new CkmEddsaParams(phFlag: false)),
        "Ed448ph" => new([0x06, 0x03, 0x2B, 0x65, 0x71],
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49",
            "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880",
            "616263",
            "822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00",
            new CkmEddsaParams(phFlag: true)),
        _ => throw new ArgumentOutOfRangeException(nameof(variant), variant, null),
    };

    // EdDSA is deterministic, so the token signs RFC 8032's message to RFC 8032's signature, under the variant's
    // CK_EDDSA_PARAMS, and verifies it; a signature with one byte changed does not verify. signsPureEdDsa records a
    // module that ignores the parameters: its signature is then the pure EdDSA one, the one it makes without them.
    internal static void Assert_EdDsa_Rfc8032Variant_SignsTheKnownAnswer(IPkcs11Backend backend, string variant, bool signsPureEdDsa = false)
    {
        backend.RequireMechanism(CKM.CKM_EDDSA);
        EdDsaVector v = EdDsaVectorFor(variant);
        byte[] message = Convert.FromHexString(v.Message);
        byte[] expected = Convert.FromHexString(v.Signature);
        byte[] point = Convert.FromHexString(v.Public);
        WithSession(backend, session =>
        {
            using var privateTemplate = new Template(
            [
                new(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS),
                new(CKA.CKA_TOKEN, false), new(CKA.CKA_SIGN, true), new(CKA.CKA_EC_PARAMS, v.Oid),
                new(CKA.CKA_VALUE, Convert.FromHexString(v.Secret)),
            ]);
            using var publicTemplate = new Template(
            [
                new(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_EC_EDWARDS),
                new(CKA.CKA_TOKEN, false), new(CKA.CKA_VERIFY, true), new(CKA.CKA_EC_PARAMS, v.Oid),
                new(CKA.CKA_EC_POINT, backend.EcxPointIsDerEncoded ? [0x04, (byte)point.Length, .. point] : point),
            ]);
            ObjectHandle priv = OrSkip(() => session.CreateObject(privateTemplate.Attributes), $"an {variant} key");
            ObjectHandle pub = session.CreateObject(publicTemplate.Attributes);
            try
            {
                var eddsa = new Mechanism(CKM.CKM_EDDSA, v.Parameters);
                byte[] signature = OrSkip(() => session.Sign(eddsa, priv, message), $"{variant} signing");
                if (signsPureEdDsa)
                {
                    Assert.NotEqual(expected, signature);
                    Assert.Equal(session.Sign(new Mechanism(CKM.CKM_EDDSA), priv, message), signature);
                    return;
                }
                Assert.Equal(expected, signature);
                Assert.True(session.Verify(eddsa, pub, message, expected));
                byte[] tampered = [.. expected];
                tampered[^1] ^= 0x01;
                Assert.False(session.Verify(eddsa, pub, message, tampered));
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        });
    }

    // === ECDSA on further curves ================================================

    public static TheoryData<string> EcdsaCurves => ["secp224r1", "secp256k1", "brainpoolP256r1"];

    private static (byte[] Params, string Oid, int FieldBytes) EcCurve(string curve) => curve switch
    {
        "secp224r1" => ([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21], "1.3.132.0.33", 28),
        "secp256k1" => ([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A], "1.3.132.0.10", 32),
        "brainpoolP256r1" => ([0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07], "1.3.36.3.3.2.8.1.1.7", 32),
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, null),
    };

    // On a curve the rest of the suite does not reach, a token-generated key signs a SHA-256 digest with CKM_ECDSA
    // to r || s of exactly twice the field size (PKCS#11 v3.2 §6.3.1), which .NET verifies under the key's public
    // point; and ECDSA's nonce makes two signatures of the same digest differ. keyGenRefused records a module that
    // refuses the curve with a code other than the ones for a curve it does not take.
    internal static void Assert_Ecdsa_OnTheCurve_VerifiesUnderBcl(IPkcs11Backend backend, string curve, CKR? keyGenRefused = null)
    {
        backend.RequireMechanisms(CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA);
        var (ecParams, oid, fieldBytes) = EcCurve(curve);
        WithSession(backend, session =>
        {
            // P-224 and secp256k1 are outside the default policy.
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            if (keyGenRefused is CKR refusal)
            {
                var ex = Assert.ThrowsAny<Pkcs11Exception>(() => TestKeys.GenerateEcKeyPair(session, ecParams));
                Assert.Equal(refusal, ex.ReturnValue);
                return;
            }
            var (pub, priv) = OrSkip(() => TestKeys.GenerateEcKeyPair(session, ecParams), curve);
            try
            {
                byte[] digest = SHA256.HashData(Message);
                byte[] first = session.Sign(new Mechanism(CKM.CKM_ECDSA), priv, digest);
                byte[] second = session.Sign(new Mechanism(CKM.CKM_ECDSA), priv, digest);
                Assert.Equal(2 * fieldBytes, first.Length);
                Assert.Equal(2 * fieldBytes, second.Length);
                Assert.NotEqual(first, second);

                Assert.True(session.Verify(new Mechanism(CKM.CKM_ECDSA), pub, digest, first));

                byte[] point = ReadAttribute(session, pub, CKA.CKA_EC_POINT);
                if (point.Length == 2 * fieldBytes + 3)
                    point = point[2..];
                Assert.Equal(2 * fieldBytes + 1, point.Length);
                ECDsa verifier;
                try
                {
                    verifier = ECDsa.Create(new ECParameters
                    {
                        Curve = ECCurve.CreateFromValue(oid),
                        Q = new ECPoint { X = point[1..(1 + fieldBytes)], Y = point[(1 + fieldBytes)..] },
                    });
                }
                catch (PlatformNotSupportedException)
                {
                    // .NET on macOS uses Apple's cryptography, which has none of these curves.
                    Assert.Skip($"This platform's .NET cannot verify ECDSA on {curve}; the token's side of the case passed.");
                    throw;
                }
                using (verifier)
                {
                    Assert.True(verifier.VerifyHash(digest, first), $"{curve}: .NET should verify the token's signature");
                    Assert.True(verifier.VerifyHash(digest, second));
                }
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        });
    }

    // === Digests ================================================================

    // FIPS 180-4 (via NIST's examples) and FIPS 202: "abc" and the 448-bit message, then the empty string.
    public static TheoryData<CKM, string, string> DigestVectors => new()
    {
        { CKM.CKM_SHA224, "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
        { CKM.CKM_SHA224, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" },
        { CKM.CKM_SHA3_224, "abc", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf" },
        { CKM.CKM_SHA3_224, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33" },
    };

    public static TheoryData<CKM, string, string> EmptyDigestVectors => new()
    {
        { CKM.CKM_SHA224, "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
        { CKM.CKM_SHA3_224, "", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" },
    };

    // The 224-bit digests, which .NET does not implement, give the published answers.
    internal static void Assert_Digest_KnownAnswer(IPkcs11Backend backend, CKM mechanism, string message, string expected)
    {
        backend.RequireMechanism(mechanism);
        WithSession(backend, session =>
        {
            // SHA-224 is outside the default policy.
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            Assert.Equal(Convert.FromHexString(expected), session.Digest(new Mechanism(mechanism), System.Text.Encoding.ASCII.GetBytes(message)));
        });
    }

    // C_DigestKey digests a secret key's value (PKCS#11 v3.2 §5.12): the digest of a key imported with a known
    // value is the SHA-256 of that value. refused records a module that will not digest the key, with its code.
    internal static void Assert_DigestKey_IsTheDigestOfTheKeysValue(IPkcs11Backend backend, CKR? refused = null)
    {
        backend.RequireMechanism(CKM.CKM_SHA256);
        byte[] value = [.. Enumerable.Range(0, 32).Select(i => (byte)(0xA0 ^ i))];
        WithSession(backend, session =>
        {
            ObjectHandle key = TestKeys.CreateGenericSecretKey(session, value);
            try
            {
                if (refused is CKR refusal)
                    Assert.Equal(refusal, Assert.ThrowsAny<Pkcs11Exception>(() => session.DigestKey(new Mechanism(CKM.CKM_SHA256), key)).ReturnValue);
                else
                    Assert.Equal(SHA256.HashData(value), session.DigestKey(new Mechanism(CKM.CKM_SHA256), key));
            }
            finally { session.DestroyObject(key); }
        });
    }

    // C_DigestKey digests a secret key's value only: an EC private key "cannot be digested" (CKR_KEY_INDIGESTIBLE,
    // PKCS#11 v3.2 §5.1.6: "perhaps the key isn't a secret key"; §5.12.4). After that refusal the digest either
    // goes on, so that C_DigestFinal gives the digest of the data fed before it, or was ended, so that
    // C_DigestFinal answers CKR_OPERATION_NOT_INITIALIZED; either way the next C_DigestInit succeeds.
    internal static void Assert_DigestKey_OfAPrivateKey_IsKeyIndigestible(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SHA256, CKM.CKM_EC_KEY_PAIR_GEN);
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        WithSession(backend, session =>
        {
            var sid = (NativeCULong)session.SessionId;
            var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
            try
            {
                CKR DigestInit()
                {
                    using var scope = new MechanismParameterScope();
                    CK_MECHANISM mech = new Mechanism(CKM.CKM_SHA256).Marshal(scope, out _);
                    return lowLevel.C_DigestInit(sid, in mech);
                }
                Assert.Equal(CKR.CKR_OK, DigestInit());
                Assert.Equal(CKR.CKR_OK, lowLevel.C_DigestUpdate(sid, Message));
                CKR rv = lowLevel.C_DigestKey(sid, (NativeCULong)priv.ObjectId);
                Assert.True(rv == CKR.CKR_KEY_INDIGESTIBLE, $"C_DigestKey of an EC private key returned {rv}.");

                byte[] digest = new byte[32];
                CKR final = lowLevel.C_DigestFinal(sid, digest, lengthOnly: false, out _);
                Assert.True(final is CKR.CKR_OK or CKR.CKR_OPERATION_NOT_INITIALIZED,
                    $"C_DigestFinal after the refused C_DigestKey returned {final}.");
                if (final == CKR.CKR_OK)
                    Assert.Equal(SHA256.HashData(Message), digest);
                Assert.Equal(CKR.CKR_OK, DigestInit());
                Assert.Equal(CKR.CKR_OK, lowLevel.C_Digest(sid, Message, digest, lengthOnly: false, out _));
                Assert.Equal(SHA256.HashData(Message), digest);
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        });
    }

    // === Key agreement ==========================================================

    // SP 800-56A ECC CDH for P-256 (the suite's ECDH known answer): our private scalar, the peer's point, and Z.
    private static readonly byte[] EcdhScalar = Convert.FromHexString("9428d7f39f5a4da29e1b5d58913961d8e104af34c0334e8ec08899a3fd5b8b67");
    private static readonly byte[] EcdhPeer = TestKeys.DerEcPoint(
        Convert.FromHexString("5e587250eb1e96f4374b119399d529c3272e530ca679be3105820570a3f6bb38"),
        Convert.FromHexString("ec9add0f07b0315110793e437934ae1835015713f0b30a7312213d7f9a494cdc"));
    private static readonly byte[] EcdhZ = Convert.FromHexString("05c83b263aef2b5648428467f18a7e2bb566a5a77ef5a1732cc13fedca838b71");

    // With CKD_SHA256_KDF, ECDH's output is the ANSI X9.63 KDF over Z and the shared data
    // (SHA-256(Z || 00000001 || sharedData) for 32 bytes), with and without shared data. counterStartsAtZero
    // records a module whose KDF counts from 0, and refused one that does not take the KDF, with its code.
    internal static void Assert_Ecdh_Sha256Kdf_IsX963OverZAndTheSharedData(IPkcs11Backend backend, bool counterStartsAtZero = false, CKR? refused = null)
    {
        backend.RequireMechanisms(CKM.CKM_ECDH1_DERIVE, CKM.CKM_SHA256_HMAC);
        WithSession(backend, session =>
        {
            ObjectHandle priv = TestKeys.ImportEcP256PrivateKey(session, EcdhScalar);
            try
            {
                foreach (byte[] shared in new[] { Array.Empty<byte>(), "kl-ecdh-shared-info"u8.ToArray() })
                {
                    var ecdh = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, EcdhPeer, shared));
                    if (refused is CKR refusal)
                    {
                        Assert.Equal(refusal, Assert.ThrowsAny<Pkcs11Exception>(() => HmacOfDerived(session, ecdh, priv, 32)).ReturnValue);
                        continue;
                    }
                    byte[] expected = SHA256.HashData([.. EcdhZ, 0, 0, 0, counterStartsAtZero ? (byte)0 : (byte)1, .. shared]);
                    Assert.Equal(HMACSHA256.HashData(expected, Message), OrSkip(() => HmacOfDerived(session, ecdh, priv, 32), "CKD_SHA256_KDF"));
                }
            }
            finally { session.DestroyObject(priv); }
        });
    }

    // On a curve whose cofactor is 1, cofactor ECDH (CKM_ECDH1_COFACTOR_DERIVE) agrees the same Z as plain ECDH.
    internal static void Assert_EcdhCofactor_OnP256_AgreesThePlainSecret(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_ECDH1_COFACTOR_DERIVE, CKM.CKM_SHA256_HMAC);
        WithSession(backend, session =>
        {
            // The raw secret (CKD_NULL) is outside the default policy.
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            ObjectHandle priv = TestKeys.ImportEcP256PrivateKey(session, EcdhScalar);
            try
            {
                var cofactor = new Mechanism(CKM.CKM_ECDH1_COFACTOR_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, EcdhPeer));
                Assert.Equal(HMACSHA256.HashData(EcdhZ, Message), HmacOfDerived(session, cofactor, priv, 32));
            }
            finally { session.DestroyObject(priv); }
        });
    }

    // X25519 with a peer key of small order agrees the all-zero secret, which RFC 7748 §6.1 tells an
    // implementation to check for and refuse. acceptsLowOrderPeer records a module that derives it anyway; the
    // case then pins that the secret it derived is the zero one.
    internal static void Assert_X25519_LowOrderPeer_IsRefused(IPkcs11Backend backend, bool acceptsLowOrderPeer = false)
    {
        backend.RequireMechanisms(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKM.CKM_ECDH1_DERIVE, CKM.CKM_SHA256_HMAC);
        byte[] x25519 = [0x06, 0x03, 0x2B, 0x65, 0x6E];
        WithSession(backend, session =>
        {
            using var pubTemplate = new Template(
            [
                new(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_EC_MONTGOMERY),
                new(CKA.CKA_TOKEN, false), new(CKA.CKA_EC_PARAMS, x25519),
            ]);
            using var privTemplate = new Template(
            [
                new(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_EC_MONTGOMERY),
                new(CKA.CKA_TOKEN, false), new(CKA.CKA_SENSITIVE, true), new(CKA.CKA_DERIVE, true),
            ]);
            session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN), pubTemplate.Attributes, privTemplate.Attributes, out ObjectHandle pub, out ObjectHandle priv);
            try
            {
                using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
                // u = 0, a point of order 1 (RFC 7748 §6.1; the first of the small-order points in the Curve25519 list).
                var ecdh = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, new byte[32]));
                if (acceptsLowOrderPeer)
                    Assert.Equal(HMACSHA256.HashData(new byte[32], Message), HmacOfDerived(session, ecdh, priv, 32));
                else
                    Assert.ThrowsAny<Pkcs11Exception>(() => HmacOfDerived(session, ecdh, priv, 32));
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        });
    }

    // X448, RFC 7748 §6.2: Alice's private key and Bob's public key agree the published secret.
    internal static void Assert_X448_Rfc7748_AgreesTheKnownSecret(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKM.CKM_ECDH1_DERIVE, CKM.CKM_SHA256_HMAC);
        byte[] alicePrivate = Convert.FromHexString("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
        byte[] bobPublic = Convert.FromHexString("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
        byte[] secret = Convert.FromHexString("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
        WithSession(backend, session =>
        {
            using var template = new Template(
            [
                new(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_EC_MONTGOMERY),
                new(CKA.CKA_TOKEN, false), new(CKA.CKA_DERIVE, true),
                new(CKA.CKA_EC_PARAMS, (byte[])[0x06, 0x03, 0x2B, 0x65, 0x6F]), new(CKA.CKA_VALUE, alicePrivate),
            ]);
            ObjectHandle priv = OrSkip(() => session.CreateObject(template.Attributes), "an X448 key");
            try
            {
                using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
                var ecdh = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, bobPublic));
                Assert.Equal(HMACSHA256.HashData(secret, Message), HmacOfDerived(session, ecdh, priv, 56));
            }
            finally { session.DestroyObject(priv); }
        });
    }

    // === Key derivation =========================================================

    private static readonly byte[] Ikm = [.. Enumerable.Range(0, 22).Select(i => (byte)0x0B)];
    private static readonly byte[] HkdfSalt = [.. Enumerable.Range(0, 13).Select(i => (byte)i)];
    private static readonly byte[] HkdfInfo = [.. Enumerable.Range(0xF0, 10).Select(i => (byte)i)];

    private static byte[] HmacOfDerived(Pkcs11Key baseKey, Mechanism mechanism)
    {
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Sign().Build();
        using var derived = baseKey.Derive(mechanism, template);
        try { return derived.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), Message); }
        finally { derived.Destroy(); }
    }

    // HKDF with SHA-512 gives what .NET's HKDF gives for the same key, salt and info (RFC 5869).
    internal static void Assert_Hkdf_Sha512_MatchesBcl(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_HKDF_DERIVE, CKM.CKM_SHA256_HMAC);
        using var session = backend.OpenSession();
        PropertyTestSupport.WithSecretKey(backend, session, CKK.CKK_GENERIC_SECRET, Ikm, t => t.Derive(), ikm =>
        {
            var hkdf = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA512, HkdfSalt, HkdfInfo));
            byte[] expected = HKDF.DeriveKey(HashAlgorithmName.SHA512, Ikm, 32, HkdfSalt, HkdfInfo);
            Assert.Equal(HMACSHA256.HashData(expected, Message), OrSkip(() => HmacOfDerived(ikm, hkdf), "HKDF with SHA-512"));
        });
    }

    // HKDF can take its salt from a key (CKF_HKDF_SALT_KEY): the output is the HKDF with that key's value as salt.
    internal static void Assert_Hkdf_SaltFromAKey_MatchesBcl(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_HKDF_DERIVE, CKM.CKM_SHA256_HMAC);
        using var session = backend.OpenSession();
        PropertyTestSupport.WithSecretKey(backend, session, CKK.CKK_GENERIC_SECRET, Ikm, t => t.Derive(), ikm =>
            PropertyTestSupport.WithSecretKey(backend, session, CKK.CKK_GENERIC_SECRET, HkdfSalt, t => t.Derive(), salt =>
            {
                var hkdf = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithSaltKey(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, salt, HkdfInfo));
                byte[] expected = HKDF.DeriveKey(HashAlgorithmName.SHA256, Ikm, 32, HkdfSalt, HkdfInfo);
                Assert.Equal(HMACSHA256.HashData(expected, Message), OrSkip(() => HmacOfDerived(ikm, hkdf), "an HKDF salt key"));
            }));
    }

    // CKM_SHA256_KEY_DERIVATION derives a key whose value is the SHA-256 of the base key's value (PKCS#11 v3.2
    // §6.20.6).
    internal static void Assert_Sha256KeyDerivation_IsTheDigestOfTheBaseKey(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SHA256_KEY_DERIVATION, CKM.CKM_SHA256_HMAC);
        WithSession(backend, session =>
        {
            ObjectHandle baseKey = CreateSecret(session, CKK.CKK_GENERIC_SECRET, Ikm, CKA.CKA_DERIVE);
            try
            {
                // A bare hash as a KDF is outside the default policy.
                using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
                Assert.Equal(HMACSHA256.HashData(SHA256.HashData(Ikm), Message),
                    HmacOfDerived(session, new Mechanism(CKM.CKM_SHA256_KEY_DERIVATION), baseKey, 32));
            }
            finally { session.DestroyObject(baseKey); }
        });
    }

    // === AES key wrap ===========================================================

    private static readonly byte[] Kek = [.. Enumerable.Range(0, 32).Select(i => (byte)(0x40 + i))];
    private static readonly byte[] Target = [.. Enumerable.Range(0, 32).Select(i => (byte)(0x80 + i))];

    // An AES key that can only encrypt, as an unwrapped key's template.
    private static Template UnwrappedAesTemplate() => new(
    [
        new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_AES),
        new(CKA.CKA_TOKEN, false), new(CKA.CKA_ENCRYPT, true), new(CKA.CKA_SENSITIVE, true),
    ]);

    private static void WithKekAndTarget(IPkcs11Backend backend, Action<Pkcs11SessionCore, ObjectHandle, ObjectHandle> body)
    {
        backend.RequireMechanism(CKM.CKM_AES_KEY_WRAP);
        backend.RequireMechanismFlags(CKM.CKM_AES_KEY_WRAP, f => f.Wrap && f.Unwrap, "wrap and unwrap");
        WithSession(backend, session =>
        {
            ObjectHandle kek = TestKeys.ImportAesWrappingKey(session, Kek);
            ObjectHandle target = TestKeys.ImportExtractableAesKey(session, Target);
            try { body(session, kek, target); }
            finally { session.DestroyObject(target); session.DestroyObject(kek); }
        });
    }

    // RFC 3394's IV is A6A6A6A6A6A6A6A6 (§2.2.3.1). Passed explicitly, as an 8-byte CKM_AES_KEY_WRAP parameter, it
    // wraps the key to the same blob as no parameter does. refused records a module that takes no parameter.
    internal static void Assert_AesKeyWrap_ExplicitDefaultIv_GivesTheSameBlob(IPkcs11Backend backend, CKR? refused = null)
    {
        WithKekAndTarget(backend, (session, kek, target) =>
        {
            byte[] implicitIv = session.WrapKey(new Mechanism(CKM.CKM_AES_KEY_WRAP), kek, target);
            var withIv = new Mechanism(CKM.CKM_AES_KEY_WRAP, (byte[])[0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6]);
            if (refused is CKR refusal)
            {
                Assert.Equal(refusal, Assert.ThrowsAny<Pkcs11Exception>(() => session.WrapKey(withIv, kek, target)).ReturnValue);
                return;
            }
            Assert.Equal(implicitIv, OrSkip(() => session.WrapKey(withIv, kek, target), "an explicit AES key wrap IV"));
        });
    }

    public static TheoryData<string> AesKeyWrapTampering => ["first byte", "byte 8", "last byte", "truncated", "all 0xFF", "8 bytes", "20 bytes"];

    // RFC 3394's integrity check catches any change to the 40-byte blob of a wrapped 256-bit key: unwrap refuses it
    // with CKR_WRAPPED_KEY_INVALID (PKCS#11 v3.2 §5.1.6: "the provided wrapped key is not valid"), creates no key,
    // and the session unwraps the untouched blob afterwards. Cut by a semiblock it is still a well-formed blob of a
    // 192-bit key that fails the check, so CKR_WRAPPED_KEY_INVALID too. A blob under two semiblocks (8 bytes), or
    // not a whole number of them (20 bytes), is invalid by its length alone: CKR_WRAPPED_KEY_LEN_RANGE, which
    // outranks CKR_WRAPPED_KEY_INVALID (§5.1.6). Both are in C_UnwrapKey's return values (§5.18.4).
    internal static void Assert_AesKeyWrap_TamperedBlob_IsRefused(IPkcs11Backend backend, string tampering)
    {
        WithKekAndTarget(backend, (session, kek, target) =>
        {
            var kw = new Mechanism(CKM.CKM_AES_KEY_WRAP);
            byte[] blob = session.WrapKey(kw, kek, target);
            Assert.Equal(40, blob.Length);
            byte[] bad = tampering switch
            {
                "first byte" => Flip(blob, 0),
                "byte 8" => Flip(blob, 8),
                "last byte" => Flip(blob, blob.Length - 1),
                "truncated" => blob[..^8],
                "all 0xFF" => [.. Enumerable.Repeat((byte)0xFF, blob.Length)],
                "8 bytes" => blob[..8],
                "20 bytes" => blob[..20],
                _ => throw new ArgumentOutOfRangeException(nameof(tampering), tampering, null),
            };
            CKR expected = bad.Length < 16 || bad.Length % 8 != 0 ? CKR.CKR_WRAPPED_KEY_LEN_RANGE : CKR.CKR_WRAPPED_KEY_INVALID;

            using Template template = UnwrappedAesTemplate();
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.UnwrapKey(kw, kek, bad, template.Attributes));
            Assert.Equal(expected, ex.ReturnValue);
            session.DestroyObject(session.UnwrapKey(kw, kek, blob, template.Attributes));
        });
    }

    private static byte[] Flip(byte[] data, int index)
    {
        byte[] copy = [.. data];
        copy[index] ^= 0x01;
        return copy;
    }

    // Only an AES key unwraps under CKM_AES_KEY_WRAP: a generic secret with CKA_UNWRAP set is refused
    // (CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, or CKR_KEY_TYPE_INCONSISTENT as some modules answer).
    // acceptsAGenericSecret records a module that unwraps with it as if it were the AES key of that value.
    internal static void Assert_AesKeyWrap_UnwrapWithAGenericSecret_IsRefused(IPkcs11Backend backend, bool acceptsAGenericSecret = false)
    {
        WithKekAndTarget(backend, (session, kek, target) =>
        {
            var kw = new Mechanism(CKM.CKM_AES_KEY_WRAP);
            byte[] blob = session.WrapKey(kw, kek, target);
            ObjectHandle generic = OrSkip(() => CreateSecret(session, CKK.CKK_GENERIC_SECRET, Kek, CKA.CKA_UNWRAP), "a generic secret that can unwrap");
            using Template template = UnwrappedAesTemplate();
            try
            {
                if (acceptsAGenericSecret)
                    session.DestroyObject(session.UnwrapKey(kw, generic, blob, template.Attributes));
                else
                    Assert.ThrowsAny<Pkcs11Exception>(() => session.UnwrapKey(kw, generic, blob, template.Attributes));
            }
            finally { session.DestroyObject(generic); }
        });
    }

    // === Post-quantum ===========================================================

    private static Pkcs11Key GeneratePqcPair(Pkcs11Session session, CKK keyType, CKM generation, ulong parameterSet)
    {
        string label = $"kl-alg-{Guid.NewGuid():N}";
        var pub = ObjectTemplate.ForPublicKey(keyType).Label(label).Attribute(CKA.CKA_PARAMETER_SET, parameterSet);
        var priv = ObjectTemplate.ForPrivateKey(keyType).Label(label);
        bool kem = keyType == CKK.CKK_ML_KEM;
        using var pubTemplate = (kem ? pub.Attribute(CKA.CKA_ENCAPSULATE, true) : pub.Verify()).Build();
        using var privTemplate = (kem ? priv.Attribute(CKA.CKA_DECAPSULATE, true) : priv.Sign()).Build();
        return session.GenerateKeyPair(new Mechanism(generation), pubTemplate, privTemplate);
    }

    // A ciphertext encapsulated to one ML-KEM-768 key decapsulates under another without an error, to a secret
    // other than the one encapsulated (FIPS 203 implicit rejection).
    internal static void Assert_MlKem_DecapsulationUnderAnotherKey_GivesAnotherSecret(IPkcs11Backend backend)
    {
        backend.RequireMlKemParameterSet(MLKemAlgorithm.MLKem768.EncapsulationKeySizeInBytes);
        using var session = backend.OpenSession();
        // Encapsulate and Decapsulate return the shared secret as bytes, which the default policy refuses.
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using var recipient = GeneratePqcPair(session, CKK.CKK_ML_KEM, CKM.CKM_ML_KEM_KEY_PAIR_GEN, (ulong)CkpMlKem.CKP_ML_KEM_768);
        using var other = GeneratePqcPair(session, CKK.CKK_ML_KEM, CKM.CKM_ML_KEM_KEY_PAIR_GEN, (ulong)CkpMlKem.CKP_ML_KEM_768);
        try
        {
            using var toRecipient = new MLKemPkcs11(recipient);
            using var underOther = new MLKemPkcs11(other);
            toRecipient.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret);

            Assert.Equal(sharedSecret, toRecipient.Decapsulate(ciphertext));
            byte[] rejected = underOther.Decapsulate(ciphertext);
            Assert.Equal(sharedSecret.Length, rejected.Length);
            Assert.NotEqual(sharedSecret, rejected);
        }
        finally { recipient.Destroy(); other.Destroy(); }
    }

    // A HashML-DSA signature names the hash it was made over (FIPS 204 §5.4): one over SHA-256(m) does not verify
    // as one over SHA-384(m).
    internal static void Assert_HashMlDsa_UnderAnotherHash_DoesNotVerify(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKM.CKM_HASH_ML_DSA);
        using var session = backend.OpenSession();
        using var key = GeneratePqcPair(session, CKK.CKK_ML_DSA, CKM.CKM_ML_DSA_KEY_PAIR_GEN, (ulong)CkpMlDsa.CKP_ML_DSA_65);
        try
        {
            var sha256 = new Mechanism(CKM.CKM_HASH_ML_DSA, new CkmHashPqcSignParams(CKM.CKM_SHA256));
            var sha384 = new Mechanism(CKM.CKM_HASH_ML_DSA, new CkmHashPqcSignParams(CKM.CKM_SHA384));
            byte[] signature = key.Sign(sha256, SHA256.HashData(Message));

            Assert.True(key.Verify(sha256, SHA256.HashData(Message), signature));
            Assert.False(key.Verify(sha384, SHA384.HashData(Message), signature));
        }
        finally { key.Destroy(); }
    }

    // === Saved operation state ==================================================

    // A digest's state saved with C_GetOperationState after the first part, and restored with C_SetOperationState
    // in another session, finishes there to the digest of both parts (PKCS#11 v3.2 §5.6). unsaveable records a
    // module that refuses to save it, and restoreRefused one that refuses to restore it in another session, each
    // with the code it gives.
    internal static void Assert_DigestState_SavedAndRestored_FinishesTheDigest(IPkcs11Backend backend, CKR? unsaveable = null, CKR? restoreRefused = null)
    {
        backend.RequireMechanism(CKM.CKM_SHA256);
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        byte[] part1 = "the quick brown fox "u8.ToArray();
        byte[] part2 = "jumps over the lazy dog"u8.ToArray();
        WithSession(backend, session =>
        {
            var sid = (NativeCULong)session.SessionId;
            using (var scope = new MechanismParameterScope())
            {
                CK_MECHANISM mech = new Mechanism(CKM.CKM_SHA256).Marshal(scope, out _);
                Assert.Equal(CKR.CKR_OK, lowLevel.C_DigestInit(sid, in mech));
            }
            Assert.Equal(CKR.CKR_OK, lowLevel.C_DigestUpdate(sid, part1));

            CKR rv = lowLevel.C_GetOperationState(sid, default, lengthOnly: true, out NativeCULong length);
            if (unsaveable is CKR refusal)
            {
                Assert.Equal(refusal, rv);
                return;
            }
            Assert.Equal(CKR.CKR_OK, rv);
            byte[] state = new byte[(int)(ulong)length];
            Assert.Equal(CKR.CKR_OK, lowLevel.C_GetOperationState(sid, state, lengthOnly: false, out length));
            state = state[..(int)(ulong)length];

            Assert.Equal(CKR.CKR_OK, lowLevel.C_OpenSession(backend.SlotId, (NativeCULong)(CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), out NativeCULong other));
            try
            {
                CKR restored = lowLevel.C_SetOperationState(other, state, default, default);
                if (restoreRefused is CKR restoreRefusal)
                {
                    Assert.Equal(restoreRefusal, restored);
                    return;
                }
                Assert.Equal(CKR.CKR_OK, restored);
                Assert.Equal(CKR.CKR_OK, lowLevel.C_DigestUpdate(other, part2));
                byte[] digest = new byte[32];
                Assert.Equal(CKR.CKR_OK, lowLevel.C_DigestFinal(other, digest, lengthOnly: false, out _));
                Assert.Equal(SHA256.HashData([.. part1, .. part2]), digest);
            }
            finally { lowLevel.C_CloseSession(other); }

            // The saving session still holds its own operation, and finishes it to the digest of the first part.
            byte[] own = new byte[32];
            Assert.Equal(CKR.CKR_OK, lowLevel.C_DigestFinal(sid, own, lengthOnly: false, out _));
            Assert.Equal(SHA256.HashData(part1), own);
        });
    }

    public static TheoryData<string> OperationStateMisuses =>
    [
        "save with no operation", "restore random bytes", "restore a truncated state",
        "restore with an encryption key", "restore with an authentication key",
    ];

    // The refusals §5.6.6 and §5.6.7 name, for a SHA-256 digest's state saved after one part:
    // C_GetOperationState with no operation active answers CKR_OPERATION_NOT_INITIALIZED; C_SetOperationState of
    // random bytes of the saved state's length, or of the state cut by its last byte, answers
    // CKR_SAVED_STATE_INVALID; and restoring it with an encryption or authentication key, which a digest does
    // not use, answers CKR_KEY_NOT_NEEDED (§5.1.6). Both functions are optional: a module without them answers
    // CKR_FUNCTION_NOT_SUPPORTED, and the rows that need a saved state skip where the module cannot save one
    // (CKR_STATE_UNSAVEABLE), as DigestState_SavedAndRestored records per backend; there the random bytes are
    // 64. Whether a refused restore
    // leaves the session's operation as it was is not stated, so only the code is asserted. The state is
    // restored into the session that saved it.
    internal static void Assert_OperationState_Misuse_IsRefused(IPkcs11Backend backend, string misuse)
    {
        backend.RequireMechanism(CKM.CKM_SHA256);
        LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
        WithSession(backend, session =>
        {
            var sid = (NativeCULong)session.SessionId;
            if (misuse == "save with no operation")
            {
                CKR none = lowLevel.C_GetOperationState(sid, default, lengthOnly: true, out _);
                Assert.True(none is CKR.CKR_OPERATION_NOT_INITIALIZED or CKR.CKR_FUNCTION_NOT_SUPPORTED,
                    $"C_GetOperationState with no operation active returned {none}.");
                return;
            }

            using (var scope = new MechanismParameterScope())
            {
                CK_MECHANISM mech = new Mechanism(CKM.CKM_SHA256).Marshal(scope, out _);
                Assert.Equal(CKR.CKR_OK, lowLevel.C_DigestInit(sid, in mech));
            }
            Assert.Equal(CKR.CKR_OK, lowLevel.C_DigestUpdate(sid, Message));
            CKR rv = lowLevel.C_GetOperationState(sid, default, lengthOnly: true, out NativeCULong length);
            if (misuse == "restore random bytes" && rv is CKR.CKR_FUNCTION_NOT_SUPPORTED or CKR.CKR_STATE_UNSAVEABLE)
            {
                // No state to take the length of: 64 random bytes, refused as invalid by a module that has the
                // function, or as not supported by one that has neither.
                CKR random = lowLevel.C_SetOperationState(sid, RandomNumberGenerator.GetBytes(64), default, default);
                Assert.True(random is CKR.CKR_SAVED_STATE_INVALID or CKR.CKR_FUNCTION_NOT_SUPPORTED,
                    $"C_SetOperationState of 64 random bytes returned {random} (C_GetOperationState returned {rv}).");
                return;
            }
            if (rv is CKR.CKR_FUNCTION_NOT_SUPPORTED or CKR.CKR_STATE_UNSAVEABLE)
                Assert.Skip($"The module does not save a digest's state ({rv}).");
            Assert.Equal(CKR.CKR_OK, rv);
            byte[] state = new byte[(int)(ulong)length];
            Assert.Equal(CKR.CKR_OK, lowLevel.C_GetOperationState(sid, state, lengthOnly: false, out length));
            state = state[..(int)(ulong)length];

            ObjectHandle aes = TestKeys.CreateAes256Key(session, RandomNumberGenerator.GetBytes(32));
            ObjectHandle mac = TestKeys.CreateGenericSecretKey(session, RandomNumberGenerator.GetBytes(32));
            try
            {
                (CKR expected, CKR restored) = misuse switch
                {
                    "restore random bytes" => (CKR.CKR_SAVED_STATE_INVALID,
                        lowLevel.C_SetOperationState(sid, RandomNumberGenerator.GetBytes(state.Length), default, default)),
                    "restore a truncated state" => (CKR.CKR_SAVED_STATE_INVALID,
                        lowLevel.C_SetOperationState(sid, state.AsSpan(0, state.Length - 1), default, default)),
                    "restore with an encryption key" => (CKR.CKR_KEY_NOT_NEEDED,
                        lowLevel.C_SetOperationState(sid, state, (NativeCULong)aes.ObjectId, default)),
                    "restore with an authentication key" => (CKR.CKR_KEY_NOT_NEEDED,
                        lowLevel.C_SetOperationState(sid, state, default, (NativeCULong)mac.ObjectId)),
                    _ => throw new ArgumentOutOfRangeException(nameof(misuse), misuse, null),
                };
                Assert.True(restored == expected, $"C_SetOperationState ({misuse}) was expected to return {expected} but returned {restored}.");
            }
            finally { session.DestroyObject(mac); session.DestroyObject(aes); }
        });
    }
}
