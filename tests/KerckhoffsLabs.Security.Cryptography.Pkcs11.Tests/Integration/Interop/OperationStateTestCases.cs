using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// The cases reach CKM_AES_CBC, and CKM_RSA_PKCS for signatures with message recovery, through the raw
// dispatch, past the session's policy, which the compile-time policy analyzer cannot see, so its warnings
// are suppressed for this file only.
#pragma warning disable KLPKCS11008, KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>
/// The return codes a module gives for calls that break the operation state machine or misuse a mechanism,
/// a key or a handle, checked on every real backend through the raw dispatch: an operation that was never
/// started (<c>CKR_OPERATION_NOT_INITIALIZED</c>), one started twice (<c>CKR_OPERATION_ACTIVE</c>), a
/// mechanism of the wrong kind (<c>CKR_MECHANISM_INVALID</c>), a key of the wrong type, a destroyed key,
/// input that is not a whole number of blocks, a ciphertext too short to decrypt, and the session's cancel
/// functions.
/// </summary>
/// <remarks>
/// <para>
/// The library maps these codes to its exceptions and, for some of them, recovers: it cancels an operation a
/// module kept after an error, and it reads an operation's absence from <c>CKR_OPERATION_NOT_INITIALIZED</c>.
/// A module that answers with another code, or with <c>CKR_OK</c>, breaks that reading; each wrapper names
/// the code its backend gives where it differs from the specification.
/// </para>
/// <para>
/// Every case runs in a session of its own, which it closes, so no operation it leaves active reaches the next.
/// </para>
/// </remarks>
internal static class OperationStateTestCases
{
    private static readonly byte[] Message = "the quick brown fox jumps over the lazy dog"u8.ToArray();
    // Not all zeros: Craton HSM refuses an all-zero CBC IV with CKR_MECHANISM_PARAM_INVALID.
    private static readonly byte[] Iv = [.. Enumerable.Range(1, 16).Select(i => (byte)i)];

    private static void WithSession(IPkcs11Backend backend, Action<LowLevelPkcs11Library, NativeCULong, Pkcs11SessionCore> body)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            body(backend.Library.LowLevelLibrary!, (NativeCULong)session.SessionId, session);
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    private static void AssertRv(CKR expected, CKR actual, string call) =>
        Assert.True(actual == expected, $"{call} was expected to return {expected} but returned {actual}.");

    private static void AssertRvIn(CKR[] expected, CKR actual, string call) =>
        Assert.True(expected.Contains(actual), $"{call} was expected to return one of {string.Join(", ", expected)} but returned {actual}.");

    private delegate CKR KeyedInit(NativeCULong session, in CK_MECHANISM mechanism, NativeCULong key);

    private static CKR Init(KeyedInit init, NativeCULong sid, Mechanism mechanism, ObjectHandle key)
    {
        using var scope = new MechanismParameterScope();
        CK_MECHANISM mech = mechanism.Marshal(scope, out _);
        return init(sid, in mech, (NativeCULong)key.ObjectId);
    }

    private static CKR DigestInit(LowLevelPkcs11Library lowLevel, NativeCULong sid, Mechanism mechanism)
    {
        using var scope = new MechanismParameterScope();
        CK_MECHANISM mech = mechanism.Marshal(scope, out _);
        return lowLevel.C_DigestInit(sid, in mech);
    }

    // After a case, the session can still run an operation: the call under test did not leave one behind.
    private static void AssertDigestStillRuns(LowLevelPkcs11Library lowLevel, NativeCULong sid)
    {
        AssertRv(CKR.CKR_OK, DigestInit(lowLevel, sid, new Mechanism(CKM.CKM_SHA256)), "C_DigestInit afterwards");
        byte[] digest = new byte[32];
        AssertRv(CKR.CKR_OK, lowLevel.C_Digest(sid, Message, digest, lengthOnly: false, out _), "C_Digest afterwards");
        Assert.Equal(SHA256.HashData(Message), digest);
    }

    // Signatures with message recovery are checked with CKM_RSA_PKCS, the one mechanism the backends offer
    // them for (§6.1.6); its flags say whether this module does.
    private static void RequireRecover(IPkcs11Backend backend, bool sign) =>
        backend.RequireMechanismFlags(CKM.CKM_RSA_PKCS, f => sign ? f.SignRecover : f.VerifyRecover, sign ? "CKF_SIGN_RECOVER" : "CKF_VERIFY_RECOVER");

    // === CKR_OPERATION_NOT_INITIALIZED ==========================================

    public static TheoryData<string> CallsWithoutInit =>
    [
        "C_Digest", "C_DigestUpdate", "C_DigestFinal",
        "C_Encrypt", "C_EncryptUpdate", "C_EncryptFinal",
        "C_Decrypt", "C_DecryptUpdate", "C_DecryptFinal",
        "C_Sign", "C_SignUpdate", "C_SignFinal",
        "C_Verify", "C_VerifyUpdate", "C_VerifyFinal",
        "C_FindObjects", "C_FindObjectsFinal",
        "C_SignRecover", "C_VerifyRecover", "C_VerifyRecover with a sign active",
    ];

    // A call that continues or ends an operation the session never started answers
    // CKR_OPERATION_NOT_INITIALIZED (PKCS#11 v3.1 §5.2). The library takes that code, after a module ended an
    // operation on an error, as the signal to start it again. The recover rows run where CKM_RSA_PKCS has
    // CKF_SIGN_RECOVER or CKF_VERIFY_RECOVER, the only sign of a module that implements the function. An active
    // signature is no verification with recovery (§5.15.6): C_VerifyRecover with a C_SignInit active has
    // nothing to continue either, and the signature is still there to finish.
    internal static void Assert_CallWithoutInit_IsOperationNotInitialized(IPkcs11Backend backend, string call, CKR expected = CKR.CKR_OPERATION_NOT_INITIALIZED)
    {
        backend.RequireMechanism(CKM.CKM_SHA256);
        if (call == "C_SignRecover")
            RequireRecover(backend, sign: true);
        else if (call.StartsWith("C_VerifyRecover", StringComparison.Ordinal))
            RequireRecover(backend, sign: false);
        if (call == "C_VerifyRecover with a sign active")
            backend.RequireMechanisms([CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA]);
        WithSession(backend, (lowLevel, sid, session) =>
        {
            byte[] output = new byte[64];
            byte[] signature = new byte[64];
            NativeCULong[] handles = new NativeCULong[4];
            if (call == "C_VerifyRecover with a sign active")
            {
                var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
                try
                {
                    var ecdsa = new Mechanism(CKM.CKM_ECDSA);
                    byte[] digest = SHA256.HashData(Message);
                    AssertRv(CKR.CKR_OK, Init(lowLevel.C_SignInit, sid, ecdsa, priv), "C_SignInit");
                    AssertRv(expected, lowLevel.C_VerifyRecover(sid, signature, output, lengthOnly: false, out _), call);
                    AssertRv(CKR.CKR_OK, lowLevel.C_Sign(sid, digest, signature, lengthOnly: false, out _), "C_Sign of the active signature");
                    Assert.True(session.Verify(ecdsa, pub, digest, signature));
                }
                finally { session.DestroyObject(priv); session.DestroyObject(pub); }
                AssertDigestStillRuns(lowLevel, sid);
                return;
            }
            CKR rv = call switch
            {
                "C_Digest" => lowLevel.C_Digest(sid, Message, output, lengthOnly: false, out _),
                "C_DigestUpdate" => lowLevel.C_DigestUpdate(sid, Message),
                "C_DigestFinal" => lowLevel.C_DigestFinal(sid, output, lengthOnly: false, out _),
                "C_Encrypt" => lowLevel.C_Encrypt(sid, Message, output, lengthOnly: false, out _),
                "C_EncryptUpdate" => lowLevel.C_EncryptUpdate(sid, Message, output, lengthOnly: false, out _),
                "C_EncryptFinal" => lowLevel.C_EncryptFinal(sid, output, lengthOnly: false, out _),
                "C_Decrypt" => lowLevel.C_Decrypt(sid, output, output, lengthOnly: false, out _),
                "C_DecryptUpdate" => lowLevel.C_DecryptUpdate(sid, output, output, lengthOnly: false, out _),
                "C_DecryptFinal" => lowLevel.C_DecryptFinal(sid, output, lengthOnly: false, out _),
                "C_Sign" => lowLevel.C_Sign(sid, Message, signature, lengthOnly: false, out _),
                "C_SignUpdate" => lowLevel.C_SignUpdate(sid, Message),
                "C_SignFinal" => lowLevel.C_SignFinal(sid, signature, lengthOnly: false, out _),
                "C_Verify" => lowLevel.C_Verify(sid, Message, signature),
                "C_VerifyUpdate" => lowLevel.C_VerifyUpdate(sid, Message),
                "C_VerifyFinal" => lowLevel.C_VerifyFinal(sid, signature),
                "C_FindObjects" => lowLevel.C_FindObjects(sid, handles, out _),
                "C_FindObjectsFinal" => lowLevel.C_FindObjectsFinal(sid),
                "C_SignRecover" => lowLevel.C_SignRecover(sid, Message.AsSpan(0, 32), output, lengthOnly: false, out _),
                "C_VerifyRecover" => lowLevel.C_VerifyRecover(sid, signature, output, lengthOnly: false, out _),
                _ => throw new ArgumentOutOfRangeException(nameof(call), call, null),
            };
            AssertRv(expected, rv, call + " without an Init");
            AssertDigestStillRuns(lowLevel, sid);
        });
    }

    // Once C_DigestFinal returns the digest, the operation is over: a further C_DigestUpdate has nothing to
    // continue.
    internal static void Assert_UpdateAfterFinal_IsOperationNotInitialized(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256);
        WithSession(backend, (lowLevel, sid, session) =>
        {
            AssertRv(CKR.CKR_OK, DigestInit(lowLevel, sid, new Mechanism(CKM.CKM_SHA256)), "C_DigestInit");
            AssertRv(CKR.CKR_OK, lowLevel.C_DigestUpdate(sid, Message), "C_DigestUpdate");
            byte[] digest = new byte[32];
            AssertRv(CKR.CKR_OK, lowLevel.C_DigestFinal(sid, digest, lengthOnly: false, out _), "C_DigestFinal");
            Assert.Equal(SHA256.HashData(Message), digest);

            AssertRv(CKR.CKR_OPERATION_NOT_INITIALIZED, lowLevel.C_DigestUpdate(sid, Message), "C_DigestUpdate after C_DigestFinal");
        });
    }

    // An operation belongs to the session that started it: another session of the same token has none.
    internal static void Assert_Operation_BelongsToItsSession(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256);
        WithSession(backend, (lowLevel, sid, session) =>
        {
            AssertRv(CKR.CKR_OK, DigestInit(lowLevel, sid, new Mechanism(CKM.CKM_SHA256)), "C_DigestInit");
            AssertRv(CKR.CKR_OK, lowLevel.C_DigestUpdate(sid, Message), "C_DigestUpdate");

            var slot = backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == backend.SlotId);
            using (var other = slot.OpenSessionCore())
            {
                var otherId = (NativeCULong)other.SessionId;
                AssertRv(CKR.CKR_OPERATION_NOT_INITIALIZED, lowLevel.C_DigestUpdate(otherId, Message), "C_DigestUpdate in another session");
            }

            byte[] digest = new byte[32];
            AssertRv(CKR.CKR_OK, lowLevel.C_DigestFinal(sid, digest, lengthOnly: false, out _), "C_DigestFinal in the first session");
            Assert.Equal(SHA256.HashData(Message), digest);
        });
    }

    // === CKR_OPERATION_ACTIVE ==================================================

    public static TheoryData<string> SecondInits => ["Digest", "Encrypt", "Decrypt", "Sign", "Verify", "FindObjects", "SignRecover", "VerifyRecover"];

    // A second Init of the same kind while one is active answers CKR_OPERATION_ACTIVE (§5.2) and leaves the
    // first operation as it was.
    internal static void Assert_SecondInit_IsOperationActive(IPkcs11Backend backend, string operation, CKR expected = CKR.CKR_OPERATION_ACTIVE)
    {
        CKM[] needed = operation switch
        {
            "Digest" => [CKM.CKM_SHA256],
            "Encrypt" or "Decrypt" => [CKM.CKM_AES_CBC],
            "Sign" or "Verify" => [CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA],
            _ => [],
        };
        backend.RequireMechanisms(needed);
        if (operation is "SignRecover" or "VerifyRecover")
            RequireRecover(backend, sign: operation == "SignRecover");

        WithSession(backend, (lowLevel, sid, session) =>
        {
            switch (operation)
            {
                case "Digest":
                    {
                        var sha256 = new Mechanism(CKM.CKM_SHA256);
                        AssertRv(CKR.CKR_OK, DigestInit(lowLevel, sid, sha256), "C_DigestInit");
                        AssertRv(expected, DigestInit(lowLevel, sid, sha256), "a second C_DigestInit");
                        byte[] digest = new byte[32];
                        AssertRv(CKR.CKR_OK, lowLevel.C_Digest(sid, Message, digest, lengthOnly: false, out _), "C_Digest of the first operation");
                        Assert.Equal(SHA256.HashData(Message), digest);
                        break;
                    }
                case "Encrypt":
                case "Decrypt":
                    {
                        byte[] rawKey = RandomNumberGenerator.GetBytes(32);
                        ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
                        try
                        {
                            var cbc = new Mechanism(CKM.CKM_AES_CBC, Iv);
                            KeyedInit init = operation == "Encrypt" ? lowLevel.C_EncryptInit : lowLevel.C_DecryptInit;
                            AssertRv(CKR.CKR_OK, Init(init, sid, cbc, key), $"C_{operation}Init");
                            AssertRv(expected, Init(init, sid, cbc, key), $"a second C_{operation}Init");

                            using var aes = Aes.Create();
                            aes.Key = rawKey;
                            byte[] block = Message.AsSpan(0, 16).ToArray();
                            byte[] input = operation == "Encrypt" ? block : aes.EncryptCbc(block, Iv, PaddingMode.None);
                            byte[] expectedOutput = operation == "Encrypt" ? aes.EncryptCbc(block, Iv, PaddingMode.None) : block;
                            byte[] output = new byte[16];
                            CKR rv = operation == "Encrypt"
                                ? lowLevel.C_Encrypt(sid, input, output, lengthOnly: false, out _)
                                : lowLevel.C_Decrypt(sid, input, output, lengthOnly: false, out _);
                            AssertRv(CKR.CKR_OK, rv, $"C_{operation} of the first operation");
                            Assert.Equal(expectedOutput, output);
                        }
                        finally { session.DestroyObject(key); }
                        break;
                    }
                case "Sign":
                case "Verify":
                    {
                        var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
                        try
                        {
                            var ecdsa = new Mechanism(CKM.CKM_ECDSA);
                            byte[] digest = SHA256.HashData(Message);
                            byte[] signature = session.Sign(ecdsa, priv, digest);
                            KeyedInit init = operation == "Sign" ? lowLevel.C_SignInit : lowLevel.C_VerifyInit;
                            ObjectHandle key = operation == "Sign" ? priv : pub;
                            AssertRv(CKR.CKR_OK, Init(init, sid, ecdsa, key), $"C_{operation}Init");
                            AssertRv(expected, Init(init, sid, ecdsa, key), $"a second C_{operation}Init");

                            if (operation == "Sign")
                            {
                                byte[] produced = new byte[64];
                                AssertRv(CKR.CKR_OK, lowLevel.C_Sign(sid, digest, produced, lengthOnly: false, out _), "C_Sign of the first operation");
                                Assert.True(session.Verify(ecdsa, pub, digest, produced));
                            }
                            else
                            {
                                AssertRv(CKR.CKR_OK, lowLevel.C_Verify(sid, digest, signature), "C_Verify of the first operation");
                            }
                        }
                        finally { session.DestroyObject(priv); session.DestroyObject(pub); }
                        break;
                    }
                case "SignRecover":
                case "VerifyRecover":
                    {
                        using var rsa = RSA.Create(2048);
                        var (pub, priv) = TestKeys.ImportRsaRecoveryKeyPair(session, rsa);
                        try
                        {
                            var pkcs1 = new Mechanism(CKM.CKM_RSA_PKCS);
                            byte[] data = TestKeys.Sha256DigestInfo(Message);
                            byte[] signature = rsa.SignData(Message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                            KeyedInit init = operation == "SignRecover" ? lowLevel.C_SignRecoverInit : lowLevel.C_VerifyRecoverInit;
                            ObjectHandle key = operation == "SignRecover" ? priv : pub;
                            AssertRv(CKR.CKR_OK, Init(init, sid, pkcs1, key), $"C_{operation}Init");
                            AssertRv(expected, Init(init, sid, pkcs1, key), $"a second C_{operation}Init");

                            byte[] output = new byte[256];
                            CKR rv = operation == "SignRecover"
                                ? lowLevel.C_SignRecover(sid, data, output, lengthOnly: false, out NativeCULong n)
                                : lowLevel.C_VerifyRecover(sid, signature, output, lengthOnly: false, out n);
                            AssertRv(CKR.CKR_OK, rv, $"C_{operation} of the first operation");
                            Assert.Equal(operation == "SignRecover" ? signature : data, output.AsSpan(0, (int)n).ToArray());
                        }
                        finally { session.DestroyObject(priv); session.DestroyObject(pub); }
                        break;
                    }
                default:
                    {
                        AssertRv(CKR.CKR_OK, lowLevel.C_FindObjectsInit(sid, []), "C_FindObjectsInit");
                        AssertRv(expected, lowLevel.C_FindObjectsInit(sid, []), "a second C_FindObjectsInit");
                        AssertRv(CKR.CKR_OK, lowLevel.C_FindObjects(sid, new NativeCULong[4], out _), "C_FindObjects of the first search");
                        AssertRv(CKR.CKR_OK, lowLevel.C_FindObjectsFinal(sid), "C_FindObjectsFinal");
                        AssertRv(CKR.CKR_OK, lowLevel.C_FindObjectsInit(sid, []), "C_FindObjectsInit after C_FindObjectsFinal");
                        AssertRv(CKR.CKR_OK, lowLevel.C_FindObjectsFinal(sid), "C_FindObjectsFinal");
                        break;
                    }
            }
        });
    }

    // === CKR_MECHANISM_INVALID =================================================

    public static TheoryData<string> MechanismsOfTheWrongKind =>
        ["digest with CKM_AES_KEY_GEN", "encrypt with CKM_SHA256", "sign with CKM_SHA256", "generate a key with CKM_SHA256", "generate a key pair with CKM_AES_KEY_GEN"];

    // A mechanism that exists but does not do what the function asks of it answers CKR_MECHANISM_INVALID
    // ("an invalid mechanism was specified to the cryptographic operation", §5.1.6): a key generator is no
    // digest, a digest is no cipher. The call creates nothing and starts nothing.
    internal static void Assert_MechanismOfTheWrongKind_IsMechanismInvalid(IPkcs11Backend backend, string misuse, CKR[]? alsoAccepted = null)
    {
        backend.RequireMechanisms([CKM.CKM_SHA256, CKM.CKM_AES_KEY_GEN]);
        CKR[] accepted = [CKR.CKR_MECHANISM_INVALID, .. alsoAccepted ?? []];
        WithSession(backend, (lowLevel, sid, session) =>
        {
            byte[] rawKey = RandomNumberGenerator.GetBytes(32);
            ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
            try
            {
                using var scope = new MechanismParameterScope();
                CKR rv;
                switch (misuse)
                {
                    case "digest with CKM_AES_KEY_GEN":
                        rv = DigestInit(lowLevel, sid, new Mechanism(CKM.CKM_AES_KEY_GEN));
                        break;
                    case "encrypt with CKM_SHA256":
                        rv = Init(lowLevel.C_EncryptInit, sid, new Mechanism(CKM.CKM_SHA256), key);
                        break;
                    case "sign with CKM_SHA256":
                        rv = Init(lowLevel.C_SignInit, sid, new Mechanism(CKM.CKM_SHA256), key);
                        break;
                    case "generate a key with CKM_SHA256":
                        {
                            CK_MECHANISM mech = new Mechanism(CKM.CKM_SHA256).Marshal(scope, out _);
                            rv = lowLevel.C_GenerateKey(sid, in mech, [], out NativeCULong generated);
                            if (rv == CKR.CKR_OK)
                                lowLevel.C_DestroyObject(sid, generated);
                            break;
                        }
                    default:
                        {
                            CK_MECHANISM mech = new Mechanism(CKM.CKM_AES_KEY_GEN).Marshal(scope, out _);
                            rv = lowLevel.C_GenerateKeyPair(sid, in mech, [], [], out NativeCULong pub, out NativeCULong priv);
                            if (rv == CKR.CKR_OK)
                            {
                                lowLevel.C_DestroyObject(sid, priv);
                                lowLevel.C_DestroyObject(sid, pub);
                            }
                            break;
                        }
                }
                AssertRvIn(accepted, rv, misuse);
                AssertDigestStillRuns(lowLevel, sid);
            }
            finally { session.DestroyObject(key); }
        });
    }

    // === A key of the wrong type ===============================================

    public static TheoryData<string> KeysOfTheWrongType =>
    [
        "ECDSA sign with an AES key", "ECDSA verify with an AES key", "AES-CBC encrypt with an EC public key",
        "RSA verify-recover with an AES key", "RSA verify-recover with an RSA private key", "RSA sign-recover with an RSA public key",
        "ECDH derive from an AES key", "HKDF derive from an EC private key",
    ];

    // Init with a key the mechanism cannot use answers CKR_KEY_TYPE_INCONSISTENT (§5.1.6). A module may answer
    // CKR_KEY_FUNCTION_NOT_PERMITTED instead, since the key also lacks the usage the mechanism needs. The
    // library checks no mechanism against a key before the call, so the module is the only guard. The derive
    // rows give the base key CKA_DERIVE, so that only its type is wrong (CKM_ECDH1_DERIVE takes an EC private
    // key, §6.3.17; CKM_HKDF_DERIVE a generic secret or HKDF key, §6.62.3), and check that C_DeriveKey made no
    // key.
    internal static void Assert_KeyOfTheWrongType_IsRefused(IPkcs11Backend backend, string misuse, CKR[]? alsoAccepted = null)
    {
        bool recover = misuse.Contains("-recover", StringComparison.Ordinal);
        if (recover)
            RequireRecover(backend, sign: misuse.Contains("sign-recover", StringComparison.Ordinal));
        else if (misuse.StartsWith("ECDH", StringComparison.Ordinal))
            backend.RequireMechanism(CKM.CKM_ECDH1_DERIVE);
        else if (misuse.StartsWith("HKDF", StringComparison.Ordinal))
            backend.RequireMechanism(CKM.CKM_HKDF_DERIVE);
        else
            backend.RequireMechanisms([CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA, CKM.CKM_AES_CBC]);
        CKR[] accepted = [CKR.CKR_KEY_TYPE_INCONSISTENT, CKR.CKR_KEY_FUNCTION_NOT_PERMITTED, .. alsoAccepted ?? []];
        WithSession(backend, (lowLevel, sid, session) =>
        {
            if (misuse.Contains("derive", StringComparison.Ordinal))
            {
                AssertDeriveFromTheWrongKeyType(lowLevel, sid, session, misuse, accepted);
                return;
            }
            ObjectHandle aesKey = TestKeys.CreateAes256Key(session, RandomNumberGenerator.GetBytes(32));
            ObjectHandle pub, priv;
            using var rsa = RSA.Create(2048);
            try
            {
                (pub, priv) = recover ? TestKeys.ImportRsaRecoveryKeyPair(session, rsa) : TestKeys.GenerateEcP256KeyPair(session);
            }
            catch
            {
                session.DestroyObject(aesKey);
                throw;
            }
            try
            {
                var pkcs1 = new Mechanism(CKM.CKM_RSA_PKCS);
                CKR rv = misuse switch
                {
                    "ECDSA sign with an AES key" => Init(lowLevel.C_SignInit, sid, new Mechanism(CKM.CKM_ECDSA), aesKey),
                    "ECDSA verify with an AES key" => Init(lowLevel.C_VerifyInit, sid, new Mechanism(CKM.CKM_ECDSA), aesKey),
                    "AES-CBC encrypt with an EC public key" => Init(lowLevel.C_EncryptInit, sid, new Mechanism(CKM.CKM_AES_CBC, Iv), pub),
                    "RSA verify-recover with an AES key" => Init(lowLevel.C_VerifyRecoverInit, sid, pkcs1, aesKey),
                    "RSA verify-recover with an RSA private key" => Init(lowLevel.C_VerifyRecoverInit, sid, pkcs1, priv),
                    "RSA sign-recover with an RSA public key" => Init(lowLevel.C_SignRecoverInit, sid, pkcs1, pub),
                    _ => throw new ArgumentOutOfRangeException(nameof(misuse), misuse, null),
                };
                AssertRvIn(accepted, rv, misuse);
                AssertDigestStillRuns(lowLevel, sid);
            }
            finally
            {
                session.DestroyObject(priv);
                session.DestroyObject(pub);
                session.DestroyObject(aesKey);
            }
        });
    }

    private static void AssertDeriveFromTheWrongKeyType(LowLevelPkcs11Library lowLevel, NativeCULong sid, Pkcs11SessionCore session, string misuse, CKR[] accepted)
    {
        string label = $"kl-wrong-base-{Guid.NewGuid():N}";
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrDerive = new ObjectAttribute(CKA.CKA_DERIVE, true);
        using var attrSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrGeneric = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var attrLen32 = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);

        ObjectHandle baseKey;
        Mechanism mechanism;
        if (misuse.StartsWith("ECDH", StringComparison.Ordinal))
        {
            using var attrAes = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
            using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32));
            baseKey = session.CreateObject([attrSecret, attrAes, attrToken, attrDerive, attrValue]);
            using var peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            ECPoint q = peer.ExportParameters(includePrivateParameters: false).Q;
            mechanism = new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(CKD.CKD_NULL, TestKeys.DerEcPoint(q.X!, q.Y!)));
        }
        else
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            baseKey = TestKeys.ImportEcP256PrivateKey(session, ecdh.ExportParameters(includePrivateParameters: true).D!);
            mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, "kl"u8));
        }
        try
        {
            using var scope = new MechanismParameterScope();
            CK_MECHANISM mech = mechanism.Marshal(scope, out _);
            CK_ATTRIBUTE[] template = [.. new[] { attrSecret, attrGeneric, attrToken, attrLen32, attrLabel }.Select(a => a.CkAttribute)];
            CKR rv = lowLevel.C_DeriveKey(sid, in mech, (NativeCULong)baseKey.ObjectId, template, out NativeCULong derived);
            if (rv == CKR.CKR_OK)
                lowLevel.C_DestroyObject(sid, derived);
            AssertRvIn(accepted, rv, misuse);
            Assert.Empty(session.FindAllObjects([attrLabel]));
            AssertDigestStillRuns(lowLevel, sid);
        }
        finally { session.DestroyObject(baseKey); }
    }

    // === An object that is not a key ===========================================

    private static readonly CKM[] AesKeyWraps = [CKM.CKM_AES_KEY_WRAP, CKM.CKM_AES_KEY_WRAP_PAD, CKM.CKM_AES_KEY_WRAP_KWP];

    public static TheoryData<string> NonKeyObjectsAsKeys =>
    [
        "C_SignInit with a data object", "C_EncryptInit with a data object",
        "C_SignInit with a certificate", "C_EncryptInit with a certificate",
        "C_WrapKey with a data object as the wrapping key", "C_UnwrapKey with a certificate as the unwrapping key",
    ];

    // A handle to an object that is not a key, named where a key is wanted, is refused, makes nothing, and leaves
    // the session able to digest. PKCS#11 v3.2 does not single out one code: §5.1.6 has CKR_KEY_HANDLE_INVALID
    // cover it ("it may be the case that the specified handle is a valid handle for an object which is not a
    // key"), but the object is no key of the mechanism's type either (CKR_KEY_TYPE_INCONSISTENT) and has none of
    // the usage attributes the operation needs (CKR_KEY_FUNCTION_NOT_PERMITTED), so an Init may answer any of
    // the three. As the wrapping key of C_WrapKey the codes are CKR_WRAPPING_KEY_HANDLE_INVALID or
    // CKR_WRAPPING_KEY_TYPE_INCONSISTENT (§5.18.3), as the unwrapping key of C_UnwrapKey their UNWRAPPING
    // counterparts (§5.18.4), or CKR_KEY_FUNCTION_NOT_PERMITTED for the missing CKA_WRAP or CKA_UNWRAP. A
    // module that read the object as a key of some type would get past all of these. A data object and an
    // X.509 certificate, both session objects.
    internal static void Assert_NonKeyObject_IsRefusedAsAKey(IPkcs11Backend backend, string misuse)
    {
        bool wrap = misuse.StartsWith("C_WrapKey", StringComparison.Ordinal);
        backend.RequireMechanism(CKM.CKM_SHA256);
        CKM keyWrap = default;
        if (misuse.StartsWith("C_SignInit", StringComparison.Ordinal))
            backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        else if (misuse.StartsWith("C_EncryptInit", StringComparison.Ordinal))
            backend.RequireMechanism(CKM.CKM_AES_CBC);
        else
        {
            Pkcs11Slot slot = backend.Library.GetSlotList().First(s => s.SlotId.Value == (ulong)backend.SlotId);
            keyWrap = AesKeyWraps.FirstOrDefault(m => backend.Supports(m) && (wrap ? slot.GetMechanismInfo(m).MechanismFlags.Wrap : slot.GetMechanismInfo(m).MechanismFlags.Unwrap));
            if (keyWrap == default)
                Assert.Skip($"Backend advertises none of {string.Join(", ", AesKeyWraps)} for {(wrap ? "CKF_WRAP" : "CKF_UNWRAP")}.");
        }

        WithSession(backend, (lowLevel, sid, session) =>
        {
            string label = $"kl-not-a-key-{Guid.NewGuid():N}";
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            ObjectHandle notAKey;
            if (misuse.Contains("data object", StringComparison.Ordinal))
            {
                using var attrData = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
                using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32));
                notAKey = session.CreateObject([attrData, attrToken, attrLabel, attrValue]);
            }
            else
            {
                using var rsa = RSA.Create(2048);
                var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=kl not a key", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
                using var attrCertificate = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE);
                using var attrX509 = new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509);
                using var attrSubject = new ObjectAttribute(CKA.CKA_SUBJECT, cert.SubjectName.RawData);
                using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, cert.RawData);
                notAKey = session.CreateObject([attrCertificate, attrX509, attrToken, attrLabel, attrSubject, attrValue]);
            }
            ObjectHandle aesKey = TestKeys.ImportExtractableAesKey(session, RandomNumberGenerator.GetBytes(32));
            try
            {
                var handle = (NativeCULong)notAKey.ObjectId;
                using var scope = new MechanismParameterScope();
                CKR rv;
                CKR[] accepted;
                if (misuse.StartsWith("C_SignInit", StringComparison.Ordinal))
                {
                    CK_MECHANISM mech = new Mechanism(CKM.CKM_SHA256_HMAC).Marshal(scope, out _);
                    rv = lowLevel.C_SignInit(sid, in mech, handle);
                    accepted = [CKR.CKR_KEY_HANDLE_INVALID, CKR.CKR_KEY_TYPE_INCONSISTENT, CKR.CKR_KEY_FUNCTION_NOT_PERMITTED];
                }
                else if (misuse.StartsWith("C_EncryptInit", StringComparison.Ordinal))
                {
                    CK_MECHANISM mech = new Mechanism(CKM.CKM_AES_CBC, Iv).Marshal(scope, out _);
                    rv = lowLevel.C_EncryptInit(sid, in mech, handle);
                    accepted = [CKR.CKR_KEY_HANDLE_INVALID, CKR.CKR_KEY_TYPE_INCONSISTENT, CKR.CKR_KEY_FUNCTION_NOT_PERMITTED];
                }
                else if (wrap)
                {
                    CK_MECHANISM mech = new Mechanism(keyWrap).Marshal(scope, out _);
                    rv = lowLevel.C_WrapKey(sid, in mech, handle, (NativeCULong)aesKey.ObjectId, new byte[64], lengthOnly: false, out _);
                    accepted = [CKR.CKR_WRAPPING_KEY_HANDLE_INVALID, CKR.CKR_WRAPPING_KEY_TYPE_INCONSISTENT, CKR.CKR_KEY_FUNCTION_NOT_PERMITTED];
                }
                else
                {
                    CK_MECHANISM mech = new Mechanism(keyWrap).Marshal(scope, out _);
                    using var attrSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                    using var attrAes = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
                    CK_ATTRIBUTE[] template = [.. new[] { attrSecret, attrAes, attrToken, attrLabel }.Select(a => a.CkAttribute)];
                    rv = lowLevel.C_UnwrapKey(sid, in mech, handle, RandomNumberGenerator.GetBytes(40), template, out NativeCULong unwrapped);
                    if (rv == CKR.CKR_OK)
                        lowLevel.C_DestroyObject(sid, unwrapped);
                    accepted = [CKR.CKR_UNWRAPPING_KEY_HANDLE_INVALID, CKR.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, CKR.CKR_KEY_FUNCTION_NOT_PERMITTED];
                }
                AssertRvIn(accepted, rv, misuse);
                using var attrSecretKey = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                Assert.Empty(session.FindAllObjects([attrSecretKey, attrLabel]));
                AssertDigestStillRuns(lowLevel, sid);
            }
            finally
            {
                session.DestroyObject(aesKey);
                session.DestroyObject(notAKey);
            }
        });
    }

    // === A destroyed key =======================================================

    public static TheoryData<string> UsesOfADestroyedKey =>
        ["C_EncryptInit", "C_DecryptInit", "C_GetAttributeValue", "C_DestroyObject", "C_SignRecoverInit", "C_VerifyRecoverInit"];

    // A handle whose object is gone answers CKR_KEY_HANDLE_INVALID where it names a key for an operation, and
    // CKR_OBJECT_HANDLE_INVALID where it names an object (§5.1.6). Most modules answer an operation's Init
    // with CKR_OBJECT_HANDLE_INVALID as well, which the library maps to the same exception family. No object is created between the destroy and
    // the call, so a module that hands out handles again has nothing to give the old one to.
    // The recover rows destroy the RSA key the Init would take, the private key for C_SignRecoverInit and the
    // public key for C_VerifyRecoverInit.
    internal static void Assert_DestroyedKey_IsRefused(IPkcs11Backend backend, string use, CKR? expected = null)
    {
        bool recover = use.Contains("RecoverInit", StringComparison.Ordinal);
        if (recover)
            RequireRecover(backend, sign: use == "C_SignRecoverInit");
        else
            backend.RequireMechanism(CKM.CKM_AES_CBC);
        WithSession(backend, (lowLevel, sid, session) =>
        {
            ObjectHandle key;
            if (recover)
            {
                using var rsa = RSA.Create(2048);
                var (pub, priv) = TestKeys.ImportRsaRecoveryKeyPair(session, rsa);
                (key, ObjectHandle kept) = use == "C_SignRecoverInit" ? (priv, pub) : (pub, priv);
                session.DestroyObject(kept);
            }
            else
            {
                key = TestKeys.CreateAes256Key(session, RandomNumberGenerator.GetBytes(32));
            }
            AssertRv(CKR.CKR_OK, lowLevel.C_DestroyObject(sid, (NativeCULong)key.ObjectId), "C_DestroyObject");

            var cbc = new Mechanism(CKM.CKM_AES_CBC, Iv);
            CKR rv;
            switch (use)
            {
                case "C_EncryptInit":
                    rv = Init(lowLevel.C_EncryptInit, sid, cbc, key);
                    break;
                case "C_DecryptInit":
                    rv = Init(lowLevel.C_DecryptInit, sid, cbc, key);
                    break;
                case "C_SignRecoverInit":
                    rv = Init(lowLevel.C_SignRecoverInit, sid, new Mechanism(CKM.CKM_RSA_PKCS), key);
                    break;
                case "C_VerifyRecoverInit":
                    rv = Init(lowLevel.C_VerifyRecoverInit, sid, new Mechanism(CKM.CKM_RSA_PKCS), key);
                    break;
                case "C_GetAttributeValue":
                    {
                        CK_ATTRIBUTE[] template = [new CK_ATTRIBUTE { type = (NativeCULong)(ulong)CKA.CKA_KEY_TYPE }];
                        rv = lowLevel.C_GetAttributeValue(sid, (NativeCULong)key.ObjectId, template);
                        break;
                    }
                default:
                    rv = lowLevel.C_DestroyObject(sid, (NativeCULong)key.ObjectId);
                    break;
            }
            CKR[] spec = use.EndsWith("Init", StringComparison.Ordinal)
                ? [CKR.CKR_KEY_HANDLE_INVALID, CKR.CKR_OBJECT_HANDLE_INVALID]
                : [CKR.CKR_OBJECT_HANDLE_INVALID];
            AssertRvIn(expected is { } e ? [e] : spec, rv, use + " with a destroyed key");
            AssertDigestStillRuns(lowLevel, sid);
        });
    }

    // === A key destroyed while its operation is active ========================

    public static TheoryData<string> OperationsWhoseKeyIsDestroyed => ["ECDSA sign", "AES-GCM encrypt"];

    // C_DestroyObject of the key an active operation uses, then the call that continues it. PKCS#11 v3.2 does
    // not say what happens (§5.7.3 does not mention active operations), so a module may refuse the destroy,
    // finish with the key it holds, or fail the operation with any error: the case asserts only that every
    // call returns, that a result returned is the right one, and that the session stays usable. The call that
    // continues is a final, which ends the operation whatever it returns (§5.2), so a new Init with another key
    // succeeds and the session still digests. A module that used the freed key would crash here, or return
    // a wrong result. keepsTheOperation records a backend that keeps the operation active after the error,
    // which the library ends with C_SessionCancel, as the case then does.
    internal static void Assert_KeyDestroyedMidOperation_SessionStaysUsable(IPkcs11Backend backend, string operation, bool keepsTheOperation = false)
    {
        bool sign = operation == "ECDSA sign";
        if (sign)
            backend.RequireMechanisms([CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA]);
        else
            backend.RequireMechanismFlags(CKM.CKM_AES_GCM, f => f.Encrypt, "CKF_ENCRYPT");
        WithSession(backend, (lowLevel, sid, session) =>
        {
            byte[] digest = SHA256.HashData(Message);
            if (sign)
            {
                var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
                var (otherPub, otherPriv) = TestKeys.GenerateEcP256KeyPair(session);
                try
                {
                    var ecdsa = new Mechanism(CKM.CKM_ECDSA);
                    AssertRv(CKR.CKR_OK, Init(lowLevel.C_SignInit, sid, ecdsa, priv), "C_SignInit");
                    CKR destroyed = lowLevel.C_DestroyObject(sid, (NativeCULong)priv.ObjectId);
                    byte[] signature = new byte[64];
                    CKR rv = lowLevel.C_Sign(sid, digest, signature, lengthOnly: false, out NativeCULong n);
                    if (rv == CKR.CKR_OK)
                        Assert.True(session.Verify(ecdsa, pub, digest, signature.AsSpan(0, (int)n).ToArray()),
                            $"C_Sign after C_DestroyObject of its key (which returned {destroyed}) returned a signature that does not verify.");

                    if (keepsTheOperation && rv != CKR.CKR_OK)
                    {
                        AssertRv(CKR.CKR_OPERATION_ACTIVE, Init(lowLevel.C_SignInit, sid, ecdsa, otherPriv), $"C_SignInit with another key after C_Sign returned {rv}");
                        AssertRv(CKR.CKR_OK, lowLevel.C_SessionCancel(sid, (NativeCULong)CKF.CKF_SIGN), "C_SessionCancel(CKF_SIGN)");
                    }
                    AssertRv(CKR.CKR_OK, Init(lowLevel.C_SignInit, sid, ecdsa, otherPriv), $"C_SignInit with another key after C_Sign returned {rv}");
                    AssertRv(CKR.CKR_OK, lowLevel.C_Sign(sid, digest, signature, lengthOnly: false, out n), "C_Sign with the other key");
                    Assert.True(session.Verify(ecdsa, otherPub, digest, signature.AsSpan(0, (int)n).ToArray()));
                }
                finally
                {
                    lowLevel.C_DestroyObject(sid, (NativeCULong)priv.ObjectId);
                    session.DestroyObject(pub);
                    session.DestroyObject(otherPriv);
                    session.DestroyObject(otherPub);
                }
            }
            else
            {
                byte[] rawKey = RandomNumberGenerator.GetBytes(32);
                ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
                ObjectHandle other = TestKeys.CreateAes256Key(session, RandomNumberGenerator.GetBytes(32));
                try
                {
                    byte[] nonce = RandomNumberGenerator.GetBytes(12);
                    byte[] expected = new byte[Message.Length + 16];
                    using (var aes = new AesGcm(rawKey, 16))
                        aes.Encrypt(nonce, Message, expected.AsSpan(0, Message.Length), expected.AsSpan(Message.Length));

                    AssertRv(CKR.CKR_OK, Init(lowLevel.C_EncryptInit, sid, new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(nonce, [], 128)), key), "C_EncryptInit");
                    byte[] output = new byte[expected.Length + 16];
                    AssertRv(CKR.CKR_OK, lowLevel.C_EncryptUpdate(sid, Message.AsSpan(0, 20), output, lengthOnly: false, out NativeCULong first), "C_EncryptUpdate");
                    CKR destroyed = lowLevel.C_DestroyObject(sid, (NativeCULong)key.ObjectId);
                    int written = (int)first;
                    CKR rv = lowLevel.C_EncryptUpdate(sid, Message.AsSpan(20), output.AsSpan(written), lengthOnly: false, out NativeCULong second);
                    if (rv == CKR.CKR_OK)
                    {
                        written += (int)second;
                        rv = lowLevel.C_EncryptFinal(sid, output.AsSpan(written), lengthOnly: false, out NativeCULong last);
                        if (rv == CKR.CKR_OK)
                        {
                            written += (int)last;
                            Assert.True(expected.AsSpan().SequenceEqual(output.AsSpan(0, written)),
                                $"The encryption whose key was destroyed (C_DestroyObject returned {destroyed}) finished with the wrong ciphertext.");
                        }
                    }
                    else
                    {
                        // The update failed, which ends the operation (§5.2), as a final would.
                        CKR final = lowLevel.C_EncryptFinal(sid, output, lengthOnly: false, out _);
                        Assert.True(final != CKR.CKR_OK, $"C_EncryptFinal after a C_EncryptUpdate that returned {rv} returned CKR_OK.");
                    }

                    var next = new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(RandomNumberGenerator.GetBytes(12), [], 128));
                    if (keepsTheOperation && rv != CKR.CKR_OK)
                    {
                        AssertRv(CKR.CKR_OPERATION_ACTIVE, Init(lowLevel.C_EncryptInit, sid, next, other), $"C_EncryptInit with another key after the encryption returned {rv}");
                        AssertRv(CKR.CKR_OK, lowLevel.C_SessionCancel(sid, (NativeCULong)CKF.CKF_ENCRYPT), "C_SessionCancel(CKF_ENCRYPT)");
                    }
                    AssertRv(CKR.CKR_OK, Init(lowLevel.C_EncryptInit, sid, next, other), $"C_EncryptInit with another key after the encryption returned {rv}");
                    AssertRv(CKR.CKR_OK, lowLevel.C_Encrypt(sid, Message, output, lengthOnly: false, out _), "C_Encrypt with the other key");
                }
                finally
                {
                    lowLevel.C_DestroyObject(sid, (NativeCULong)key.ObjectId);
                    session.DestroyObject(other);
                }
            }
            AssertDigestStillRuns(lowLevel, sid);
        });
    }

    // === Input that is not a whole number of blocks ============================

    public static TheoryData<CKM, int> PartialBlockEncryptions => new()
    {
        { CKM.CKM_AES_ECB, 15 }, { CKM.CKM_AES_ECB, 17 }, { CKM.CKM_AES_CBC, 1 }, { CKM.CKM_AES_CBC, 31 },
    };

    // AES-ECB and AES-CBC without padding take whole blocks: a plaintext of another length answers
    // CKR_DATA_LEN_RANGE (§5.1.6) and produces no ciphertext. A module that pads or truncates it instead
    // returns ciphertext that decrypts to something else. The error ends the operation (§5.2), so the next
    // C_EncryptInit succeeds; keepsTheOperation records a backend that keeps it active instead, which the
    // library ends with C_SessionCancel.
    internal static void Assert_PartialBlock_Encrypt_IsDataLenRange(IPkcs11Backend backend, CKM mechanism, int length,
        CKR expected = CKR.CKR_DATA_LEN_RANGE, bool keepsTheOperation = false)
    {
        backend.RequireMechanismFlags(mechanism, f => f.Encrypt, "CKF_ENCRYPT");
        WithSession(backend, (lowLevel, sid, session) =>
        {
            ObjectHandle key = TestKeys.CreateAes256Key(session, RandomNumberGenerator.GetBytes(32));
            try
            {
                var m = mechanism == CKM.CKM_AES_CBC ? new Mechanism(mechanism, Iv) : new Mechanism(mechanism);
                AssertRv(CKR.CKR_OK, Init(lowLevel.C_EncryptInit, sid, m, key), "C_EncryptInit");
                byte[] output = new byte[64];
                AssertRv(expected, lowLevel.C_Encrypt(sid, Message.AsSpan(0, length), output, lengthOnly: false, out _),
                    $"C_Encrypt of {length} bytes with {mechanism}");
                AssertRv(keepsTheOperation ? CKR.CKR_OPERATION_ACTIVE : CKR.CKR_OK, Init(lowLevel.C_EncryptInit, sid, m, key),
                    "C_EncryptInit after the refused C_Encrypt");
            }
            finally { session.DestroyObject(key); }
        });
    }

    public static TheoryData<CKM, int> PartialBlockDecryptions => new()
    {
        { CKM.CKM_AES_ECB, 15 }, { CKM.CKM_AES_ECB, 17 }, { CKM.CKM_AES_CBC, 1 }, { CKM.CKM_AES_CBC, 31 },
    };

    // The same for decryption: a ciphertext that is not a whole number of blocks answers
    // CKR_ENCRYPTED_DATA_LEN_RANGE.
    internal static void Assert_PartialBlock_Decrypt_IsEncryptedDataLenRange(IPkcs11Backend backend, CKM mechanism, int length,
        CKR expected = CKR.CKR_ENCRYPTED_DATA_LEN_RANGE, bool keepsTheOperation = false)
    {
        backend.RequireMechanismFlags(mechanism, f => f.Decrypt, "CKF_DECRYPT");
        WithSession(backend, (lowLevel, sid, session) =>
        {
            ObjectHandle key = TestKeys.CreateAes256Key(session, RandomNumberGenerator.GetBytes(32));
            try
            {
                var m = mechanism == CKM.CKM_AES_CBC ? new Mechanism(mechanism, Iv) : new Mechanism(mechanism);
                AssertRv(CKR.CKR_OK, Init(lowLevel.C_DecryptInit, sid, m, key), "C_DecryptInit");
                byte[] output = new byte[64];
                AssertRv(expected, lowLevel.C_Decrypt(sid, new byte[length], output, lengthOnly: false, out _),
                    $"C_Decrypt of {length} bytes with {mechanism}");
                AssertRv(keepsTheOperation ? CKR.CKR_OPERATION_ACTIVE : CKR.CKR_OK, Init(lowLevel.C_DecryptInit, sid, m, key),
                    "C_DecryptInit after the refused C_Decrypt");
            }
            finally { session.DestroyObject(key); }
        });
    }

    public static TheoryData<string> ShortCiphertexts =>
    [
        "AES-GCM, 0 bytes", "AES-GCM, 15 bytes", "AES-CBC-PAD, 0 bytes", "AES-CBC-PAD, 15 bytes",
        "AES-KW, 8 bytes", "AES-KW, 20 bytes", "AES-KWP, 8 bytes", "AES-KWP, 20 bytes",
    ];

    // A ciphertext no plaintext encrypts to, by its length alone, is refused by C_Decrypt with
    // CKR_ENCRYPTED_DATA_LEN_RANGE or CKR_ENCRYPTED_DATA_INVALID, which §5.10.2 leaves to the module ("either
    // ... may be returned"): AES-GCM shorter than the 16-byte tag its ciphertext ends with (§6.13.2), AES-CBC-PAD
    // shorter than a block, and AES key wrap (RFC 3394) or key wrap with padding (RFC 5649, §6.16.3) under two
    // semiblocks or not a whole number of them. The length query (a NULL buffer) is asked first, and may answer
    // CKR_OK with a length; the call that follows into a buffer must refuse. The refusal ends the operation
    // (§5.2), so the next C_DecryptInit succeeds; keepsTheOperation records a backend that keeps it active,
    // which the library ends with C_SessionCancel.
    internal static void Assert_ShortCiphertext_Decrypt_IsRefused(IPkcs11Backend backend, string ciphertext, bool keepsTheOperation = false)
    {
        string[] words = ciphertext.Split([", ", " "], StringSplitOptions.None);
        int length = int.Parse(words[1], System.Globalization.CultureInfo.InvariantCulture);
        CKM mechanism = words[0] switch
        {
            "AES-GCM" => CKM.CKM_AES_GCM,
            "AES-CBC-PAD" => CKM.CKM_AES_CBC_PAD,
            "AES-KW" => CKM.CKM_AES_KEY_WRAP,
            "AES-KWP" => CKM.CKM_AES_KEY_WRAP_KWP,
            _ => throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext, null),
        };
        backend.RequireMechanismFlags(mechanism, f => f.Decrypt, "CKF_DECRYPT");
        CKR[] accepted = [CKR.CKR_ENCRYPTED_DATA_LEN_RANGE, CKR.CKR_ENCRYPTED_DATA_INVALID];
        WithSession(backend, (lowLevel, sid, session) =>
        {
            ObjectHandle key = TestKeys.CreateAes256Key(session, RandomNumberGenerator.GetBytes(32));
            try
            {
                Mechanism m = mechanism switch
                {
                    CKM.CKM_AES_GCM => new Mechanism(mechanism, new CkmAesGcmParams(Iv[..12], [], 128)),
                    CKM.CKM_AES_CBC_PAD => new Mechanism(mechanism, Iv),
                    _ => new Mechanism(mechanism),
                };
                byte[] input = RandomNumberGenerator.GetBytes(length);
                AssertRv(CKR.CKR_OK, Init(lowLevel.C_DecryptInit, sid, m, key), "C_DecryptInit");
                CKR rv = lowLevel.C_Decrypt(sid, input, [], lengthOnly: true, out _);
                if (rv == CKR.CKR_OK)
                {
                    byte[] output = new byte[64];
                    rv = lowLevel.C_Decrypt(sid, input, output, lengthOnly: false, out _);
                    AssertRvIn(accepted, rv, $"C_Decrypt of {length} bytes with {mechanism} (the length query returned CKR_OK)");
                }
                else
                {
                    AssertRvIn(accepted, rv, $"C_Decrypt length query of {length} bytes with {mechanism}");
                }
                AssertRv(keepsTheOperation ? CKR.CKR_OPERATION_ACTIVE : CKR.CKR_OK, Init(lowLevel.C_DecryptInit, sid, m, key),
                    "C_DecryptInit after the refused C_Decrypt");
            }
            finally { session.DestroyObject(key); }
        });
    }

    // === Cancelling ============================================================

    // The legacy parallel-function calls answer CKR_FUNCTION_NOT_PARALLEL from every module that does not
    // run functions in parallel (§5.21), which is every module this library supports.
    internal static void Assert_LegacyParallelFunctions_AreNotParallel(IPkcs11Backend backend, CKR expected = CKR.CKR_FUNCTION_NOT_PARALLEL)
    {
        WithSession(backend, (lowLevel, sid, session) =>
        {
            AssertRv(expected, lowLevel.C_GetFunctionStatus(sid), "C_GetFunctionStatus");
            AssertRv(expected, lowLevel.C_CancelFunction(sid), "C_CancelFunction");
        });
    }

    // C_SessionCancel (v3.0) ends the operations its flags name and no other: flags of 0 name none, so the
    // digest is still active, and CKF_DIGEST ends it, so the next C_DigestInit succeeds. The library ends an
    // operation a module kept after an error this way.
    internal static void Assert_SessionCancel_EndsTheOperationsItNames(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_SHA256);
        WithSession(backend, (lowLevel, sid, session) =>
        {
            var sha256 = new Mechanism(CKM.CKM_SHA256);
            AssertRv(CKR.CKR_OK, DigestInit(lowLevel, sid, sha256), "C_DigestInit");
            CKR rv = lowLevel.C_SessionCancel(sid, (NativeCULong)0UL);
            if (rv == CKR.CKR_FUNCTION_NOT_SUPPORTED)
                Assert.Skip("The module has no C_SessionCancel (PKCS#11 v3.0).");
            AssertRv(CKR.CKR_OK, rv, "C_SessionCancel(0)");
            AssertRv(CKR.CKR_OPERATION_ACTIVE, DigestInit(lowLevel, sid, sha256), "C_DigestInit after C_SessionCancel(0)");

            AssertRv(CKR.CKR_OK, lowLevel.C_SessionCancel(sid, (NativeCULong)CKF.CKF_DIGEST), "C_SessionCancel(CKF_DIGEST)");
            AssertDigestStillRuns(lowLevel, sid);
        });
    }

    public static TheoryData<string> WrongLengthSignatures => ["C_Verify, one byte short", "C_Verify, one byte long", "C_VerifyFinal, one byte short"];

    // A C_Verify or C_VerifyFinal given a signature of the wrong length answers CKR_SIGNATURE_LEN_RANGE and
    // ends the operation (§5.2), as every C_Verify that does not return CKR_BUFFER_TOO_SMALL does. The library
    // does not rely on that: it cancels a verify that returned anything but a verdict. keepsTheOperation
    // records a backend that keeps it active, so that a module that changes its behaviour fails here.
    internal static void Assert_Verify_WrongLengthSignature_EndsTheOperation(IPkcs11Backend backend, string shape,
        CKR[]? expected = null, bool keepsTheOperation = false)
    {
        backend.RequireMechanisms([CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA_SHA256]);
        CKR[] accepted = expected ?? [CKR.CKR_SIGNATURE_LEN_RANGE, CKR.CKR_SIGNATURE_INVALID];
        WithSession(backend, (lowLevel, sid, session) =>
        {
            var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
            try
            {
                var ecdsa = new Mechanism(CKM.CKM_ECDSA_SHA256);
                byte[] signature = session.Sign(ecdsa, priv, Message);
                byte[] wrong = shape.Contains("long", StringComparison.Ordinal) ? [.. signature, 0x00] : signature[..^1];

                AssertRv(CKR.CKR_OK, Init(lowLevel.C_VerifyInit, sid, ecdsa, pub), "C_VerifyInit");
                CKR rv;
                if (shape.StartsWith("C_VerifyFinal", StringComparison.Ordinal))
                {
                    AssertRv(CKR.CKR_OK, lowLevel.C_VerifyUpdate(sid, Message), "C_VerifyUpdate");
                    rv = lowLevel.C_VerifyFinal(sid, wrong);
                }
                else
                {
                    rv = lowLevel.C_Verify(sid, Message, wrong);
                }
                AssertRvIn(accepted, rv, shape);

                CKR next = Init(lowLevel.C_VerifyInit, sid, ecdsa, pub);
                AssertRv(keepsTheOperation ? CKR.CKR_OPERATION_ACTIVE : CKR.CKR_OK, next, "C_VerifyInit after the refused signature");
                if (next == CKR.CKR_OK)
                    AssertRv(CKR.CKR_OK, lowLevel.C_Verify(sid, Message, signature), "C_Verify of the right signature");
            }
            finally { session.DestroyObject(priv); session.DestroyObject(pub); }
        });
    }
}
