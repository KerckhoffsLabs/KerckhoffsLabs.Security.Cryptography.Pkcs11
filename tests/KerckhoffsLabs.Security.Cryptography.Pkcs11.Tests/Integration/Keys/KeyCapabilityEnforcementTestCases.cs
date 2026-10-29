using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// CKM_AES_CBC_PAD is unauthenticated and gated by default; it is used here only as a convenient,
// widely-supported mechanism to probe CKA_ENCRYPT/CKA_DECRYPT enforcement, not for its own security
// properties, so the compile-time warning is suppressed for this file only. CKM_RSA_PKCS is used the same
// way, through the raw dispatch, to probe CKA_SIGN_RECOVER/CKA_VERIFY_RECOVER.
#pragma warning disable KLPKCS11008, KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Confirms every supported backend actually enforces a key's capability attributes (CKA_SIGN, CKA_VERIFY,
/// CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN_RECOVER, CKA_VERIFY_RECOVER, CKA_DERIVE, CKA_ENCAPSULATE and
/// CKA_DECAPSULATE), rather than silently permitting the operation regardless of the attribute's value, and
/// refuses with CKR_KEY_FUNCTION_NOT_PERMITTED.
/// </summary>
/// <remarks>
/// Prompted by AWS's "PKCS#11 Compliance Report for CloudHSM SDK 3.2.1" (Galois, Nov 2020), which
/// found CloudHSM's own PKCS#11 library does NOT enforce CKA_SIGN/CKA_VERIFY for AES or
/// CKK_GENERIC_SECRET keys (issues SIGN-1, VERIFY-1) — for clarity, that report notes RSA/EC keys ARE
/// correctly enforced there. That finding is specific to CloudHSM's SDK, a backend this project does
/// not target, so it doesn't transfer directly — but it identified a genuine, previously-untested
/// property worth checking against our own backends. Every key here is of the type its mechanism takes,
/// so the one code PKCS#11 v3.2 §5.1.6 gives is CKR_KEY_FUNCTION_NOT_PERMITTED ("an attempt has been made
/// to use a key for a cryptographic purpose that the key's attributes are not set to allow it to do");
/// CKR_KEY_TYPE_INCONSISTENT, which outranks it, is for a key of the wrong type. A backend that answers
/// otherwise is recorded on its wrapper.
/// </remarks>
internal static class KeyCapabilityEnforcementTestCases
{
    // The refusal is the module's, with the one code §5.1.6 gives for a key whose attributes do not allow
    // the use.
    private static void AssertKeyFunctionNotPermitted(Action use, string what)
    {
        var ex = Assert.ThrowsAny<Pkcs11Exception>(use);
        Assert.True(ex.ReturnValue == CKR.CKR_KEY_FUNCTION_NOT_PERMITTED, $"{what} returned {ex.ReturnValue}.");
    }

    private static ObjectHandle CreateGenericSecret(Pkcs11SessionCore session, byte[] rawKey, bool sign, bool verify)
    {
        using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var tok = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var s = new ObjectAttribute(CKA.CKA_SIGN, sign);
        using var v = new ObjectAttribute(CKA.CKA_VERIFY, verify);
        using var val = new ObjectAttribute(CKA.CKA_VALUE, rawKey);
        return session.CreateObject([c, t, tok, s, v, val]);
    }

    private static ObjectHandle CreateAes(Pkcs11SessionCore session, byte[] rawKey, bool encrypt, bool decrypt)
    {
        using var c = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var tok = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var e = new ObjectAttribute(CKA.CKA_ENCRYPT, encrypt);
        using var d = new ObjectAttribute(CKA.CKA_DECRYPT, decrypt);
        using var val = new ObjectAttribute(CKA.CKA_VALUE, rawKey);
        return session.CreateObject([c, t, tok, e, d, val]);
    }

    internal static void Assert_Sign_WithSignFalse_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SHA256_HMAC);
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            byte[] rawKey = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(rawKey);
            ObjectHandle key = CreateGenericSecret(session, rawKey, sign: false, verify: true);
            try
            {
                AssertKeyFunctionNotPermitted(() => session.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), key, "probe"u8.ToArray()),
                    "C_SignInit(CKM_SHA256_HMAC) with CKA_SIGN = FALSE");
            }
            finally { session.DestroyObject(key); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.Dispose(); }
    }

    internal static void Assert_Verify_WithVerifyFalse_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SHA256_HMAC);
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            byte[] rawKey = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(rawKey);
            byte[] data = "probe"u8.ToArray();

            // A real, valid MAC — so a backend that fails to enforce CKA_VERIFY would otherwise
            // report a successful verification, not just an unrelated MAC mismatch.
            ObjectHandle signOn = CreateGenericSecret(session, rawKey, sign: true, verify: true);
            byte[] validMac;
            try { validMac = session.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), signOn, data); }
            finally { session.DestroyObject(signOn); }

            ObjectHandle verifyOff = CreateGenericSecret(session, rawKey, sign: false, verify: false);
            try
            {
                AssertKeyFunctionNotPermitted(() => session.Verify(new Mechanism(CKM.CKM_SHA256_HMAC), verifyOff, data, validMac),
                    "C_VerifyInit(CKM_SHA256_HMAC) with CKA_VERIFY = FALSE");
            }
            finally { session.DestroyObject(verifyOff); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.Dispose(); }
    }

    internal static void Assert_Encrypt_WithEncryptFalse_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_CBC_PAD);
        var session = TestKeys.OpenLoggedInSession(backend);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        try
        {
            byte[] rawKey = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(rawKey);
            byte[] iv = new byte[16];
            System.Security.Cryptography.RandomNumberGenerator.Fill(iv);

            ObjectHandle key = CreateAes(session, rawKey, encrypt: false, decrypt: true);
            try
            {
                AssertKeyFunctionNotPermitted(() => session.Encrypt(new Mechanism(CKM.CKM_AES_CBC_PAD, iv), key, "probe data"u8.ToArray()),
                    "C_EncryptInit(CKM_AES_CBC_PAD) with CKA_ENCRYPT = FALSE");
            }
            finally { session.DestroyObject(key); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.Dispose(); }
    }

    internal static void Assert_Decrypt_WithDecryptFalse_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_CBC_PAD);
        var session = TestKeys.OpenLoggedInSession(backend);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        try
        {
            byte[] rawKey = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(rawKey);
            byte[] iv = new byte[16];
            System.Security.Cryptography.RandomNumberGenerator.Fill(iv);
            byte[] data = "probe data"u8.ToArray();

            // A real, valid ciphertext — so a backend that fails to enforce CKA_DECRYPT would
            // otherwise report a successful decryption, not just a padding/tag failure.
            ObjectHandle encryptOn = CreateAes(session, rawKey, encrypt: true, decrypt: true);
            byte[] validCiphertext;
            try { validCiphertext = session.Encrypt(new Mechanism(CKM.CKM_AES_CBC_PAD, iv), encryptOn, data); }
            finally { session.DestroyObject(encryptOn); }

            ObjectHandle decryptOff = CreateAes(session, rawKey, encrypt: false, decrypt: false);
            try
            {
                AssertKeyFunctionNotPermitted(() => session.Decrypt(new Mechanism(CKM.CKM_AES_CBC_PAD, iv), decryptOff, validCiphertext),
                    "C_DecryptInit(CKM_AES_CBC_PAD) with CKA_DECRYPT = FALSE");
            }
            finally { session.DestroyObject(decryptOff); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.Dispose(); }
    }

    // === Signatures with message recovery ======================================

    private delegate CKR KeyedInit(NativeCULong session, in CK_MECHANISM mechanism, NativeCULong key);

    private static CKR Init(KeyedInit init, NativeCULong sid, Mechanism mechanism, ObjectHandle key)
    {
        using var scope = new MechanismParameterScope();
        CK_MECHANISM mech = mechanism.Marshal(scope, out _);
        return init(sid, in mech, (NativeCULong)key.ObjectId);
    }

    // A key whose CKA_SIGN_RECOVER (CKA_VERIFY_RECOVER) is FALSE, though its CKA_SIGN (CKA_VERIFY) is TRUE, is
    // refused by C_SignRecoverInit (C_VerifyRecoverInit) with CKR_KEY_FUNCTION_NOT_PERMITTED: the attribute
    // "MUST be CK_TRUE" (PKCS#11 v3.2 §5.13.5, §5.15.5), and the key is of the mechanism's type, so the
    // higher-priority CKR_KEY_TYPE_INCONSISTENT does not apply (§5.1.6). The ordinary CKA_SIGN (CKA_VERIFY) is
    // no stand-in for it. CKM_RSA_PKCS, where the token offers it with CKF_SIGN_RECOVER (CKF_VERIFY_RECOVER).
    internal static void Assert_Recover_WithRecoverFalse_IsKeyFunctionNotPermitted(IPkcs11Backend backend, bool sign)
    {
        backend.RequireMechanismFlags(CKM.CKM_RSA_PKCS, f => sign ? f.SignRecover : f.VerifyRecover, sign ? "CKF_SIGN_RECOVER" : "CKF_VERIFY_RECOVER");
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var (pub, priv) = TestKeys.ImportRsaRecoveryKeyPair(session, rsa, recover: false);
            try
            {
                LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
                var sid = (NativeCULong)session.SessionId;
                CKR rv = sign
                    ? Init(lowLevel.C_SignRecoverInit, sid, new Mechanism(CKM.CKM_RSA_PKCS), priv)
                    : Init(lowLevel.C_VerifyRecoverInit, sid, new Mechanism(CKM.CKM_RSA_PKCS), pub);
                string call = sign ? "C_SignRecoverInit with CKA_SIGN_RECOVER = FALSE" : "C_VerifyRecoverInit with CKA_VERIFY_RECOVER = FALSE";
                Assert.True(rv == CKR.CKR_KEY_FUNCTION_NOT_PERMITTED, $"{call} returned {rv}.");
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.Dispose(); }
    }

    // === Derivation and key encapsulation ======================================

    public static TheoryData<string> DeriveMechanisms => ["ECDH", "HKDF"];

    // C_DeriveKey from a base key whose CKA_DERIVE is FALSE answers CKR_KEY_FUNCTION_NOT_PERMITTED and makes no
    // key (PKCS#11 v3.2 §4.8 Table 26: CKA_DERIVE "CK_TRUE if key supports key derivation"; §5.18.5). Through
    // the raw call, so that the refusal is the module's: an EC private key for CKM_ECDH1_DERIVE (CKD_NULL, the
    // case is about the attribute) and a generic secret for CKM_HKDF_DERIVE.
    internal static void Assert_Derive_WithDeriveFalse_IsKeyFunctionNotPermitted(IPkcs11Backend backend, string derivation)
    {
        backend.RequireMechanism(derivation == "ECDH" ? CKM.CKM_ECDH1_DERIVE : CKM.CKM_HKDF_DERIVE);
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            string label = $"kl-derive-false-{Guid.NewGuid():N}";
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrNoDerive = new ObjectAttribute(CKA.CKA_DERIVE, false);
            using var attrSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var attrGeneric = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
            using var attrLen32 = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);

            ObjectHandle baseKey;
            Mechanism mechanism;
            if (derivation == "ECDH")
            {
                using var ecdh = System.Security.Cryptography.ECDiffieHellman.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
                using var attrPrivate = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
                using var attrEc = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
                using var attrEcParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, TestKeys.EcP256Oid);
                using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, ecdh.ExportParameters(includePrivateParameters: true).D!);
                baseKey = session.CreateObject([attrPrivate, attrEc, attrToken, attrEcParams, attrNoDerive, attrValue]);
                using var peer = System.Security.Cryptography.ECDiffieHellman.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
                var q = peer.ExportParameters(includePrivateParameters: false).Q;
                mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, TestKeys.DerEcPoint(q.X!, q.Y!)));
            }
            else
            {
                using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
                baseKey = session.CreateObject([attrSecret, attrGeneric, attrToken, attrNoDerive, attrValue]);
                mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, "kl"u8));
            }
            try
            {
                LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
                using var scope = new MechanismParameterScope();
                CK_MECHANISM mech = mechanism.Marshal(scope, out _);
                CK_ATTRIBUTE[] template = [.. new[] { attrSecret, attrGeneric, attrToken, attrLen32, attrLabel }.Select(a => a.CkAttribute)];
                CKR rv = lowLevel.C_DeriveKey((NativeCULong)session.SessionId, in mech, (NativeCULong)baseKey.ObjectId, template, out NativeCULong derived);
                if (rv == CKR.CKR_OK)
                    lowLevel.C_DestroyObject((NativeCULong)session.SessionId, derived);
                Assert.True(rv == CKR.CKR_KEY_FUNCTION_NOT_PERMITTED, $"{derivation} C_DeriveKey from a base key with CKA_DERIVE = FALSE returned {rv}.");
                Assert.Empty(session.FindAllObjects([attrLabel]));
            }
            finally { session.DestroyObject(baseKey); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.Dispose(); }
    }

    // C_EncapsulateKey with a public key whose CKA_ENCAPSULATE is FALSE, and C_DecapsulateKey with a private key
    // whose CKA_DECAPSULATE is FALSE, answer CKR_KEY_FUNCTION_NOT_PERMITTED and make no key (PKCS#11 v3.2
    // §5.18.8, §5.18.9: the attribute "MUST be CK_TRUE"). ML-KEM-768 through the raw calls; the ciphertext to
    // decapsulate is any 1088 bytes, since ML-KEM's implicit rejection would make a key of anything.
    internal static void Assert_Kem_WithCapabilityFalse_IsKeyFunctionNotPermitted(IPkcs11Backend backend, bool encapsulate)
    {
        backend.RequireMechanisms(CKM.CKM_ML_KEM_KEY_PAIR_GEN, CKM.CKM_ML_KEM);
        backend.RequireMlKemParameterSet(1184); // ML-KEM-768
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            string label = $"kl-kem-false-{Guid.NewGuid():N}";
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrMlKem768 = new ObjectAttribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlKem.CKP_ML_KEM_768);
            using var attrEncapsulate = new ObjectAttribute(CKA.CKA_ENCAPSULATE, false);
            using var attrDecapsulate = new ObjectAttribute(CKA.CKA_DECAPSULATE, false);
            using var attrSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var attrGeneric = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), [attrToken, attrMlKem768, attrEncapsulate],
                [attrToken, attrDecapsulate], out ObjectHandle publicKey, out ObjectHandle privateKey);
            try
            {
                LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
                var sid = (NativeCULong)session.SessionId;
                using var scope = new MechanismParameterScope();
                CK_MECHANISM mech = new Mechanism(CKM.CKM_ML_KEM).Marshal(scope, out _);
                CK_ATTRIBUTE[] template = [.. new[] { attrSecret, attrGeneric, attrToken, attrLabel }.Select(a => a.CkAttribute)];
                CKR rv = encapsulate
                    ? lowLevel.C_EncapsulateKey(sid, in mech, (NativeCULong)publicKey.ObjectId, template, new byte[1088], lengthOnly: false, out _, out NativeCULong made)
                    : lowLevel.C_DecapsulateKey(sid, in mech, (NativeCULong)privateKey.ObjectId, template, System.Security.Cryptography.RandomNumberGenerator.GetBytes(1088), out made);
                if (rv == CKR.CKR_OK)
                    lowLevel.C_DestroyObject(sid, made);
                string call = encapsulate ? "C_EncapsulateKey with CKA_ENCAPSULATE = FALSE" : "C_DecapsulateKey with CKA_DECAPSULATE = FALSE";
                Assert.True(rv == CKR.CKR_KEY_FUNCTION_NOT_PERMITTED, $"{call} returned {rv}.");
                Assert.Empty(session.FindAllObjects([attrLabel]));
            }
            finally { session.DestroyObject(privateKey); session.DestroyObject(publicKey); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); session.Dispose(); }
    }
}
