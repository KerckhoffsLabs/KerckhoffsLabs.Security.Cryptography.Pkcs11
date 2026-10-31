using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>
/// Backend-agnostic tests of <see cref="CkmRsaPkcsOaepParams"/>'s optional encoding-parameter source
/// data (the <c>CKZ_DATA_SPECIFIED</c> label, PKCS#1 v2.2 §7.1) against a real token. Every other
/// RSA-OAEP test in this suite (via <c>RSAPkcs11</c> / <c>Pkcs11MechanismMap.RsaOaep</c>) passes an
/// empty label. Decrypting with the wrong label must fail exactly like decrypting with the wrong key
/// would, which shows the token folds the label into the encoding rather than validating and dropping it.
/// </summary>
internal static class EncryptRsaOaepLabelTestCases
{
    internal static void Assert_OaepWithLabel_RoundTrips(IPkcs11Backend backend)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("RSA-OAEP with an encoding-parameter label");
        byte[] label = Encoding.UTF8.GetBytes("invoice-2026-09");
        WithRsaKeyPair(backend, (session, pub, priv) =>
        {
            byte[] ciphertext = OrSkipIfOaepHashUnsupported(() => session.Encrypt(Oaep(label), pub, plaintext));

            Assert.Equal(plaintext, session.Decrypt(Oaep(label), priv, ciphertext));
        });
    }

    internal static void Assert_OaepWithWrongLabel_FailsToDecrypt(IPkcs11Backend backend)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("RSA-OAEP label mismatch must fail");
        WithRsaKeyPair(backend, (session, pub, priv) =>
        {
            byte[] ciphertext = OrSkipIfOaepHashUnsupported(
                () => session.Encrypt(Oaep(Encoding.UTF8.GetBytes("label-a")), pub, plaintext));

            // OAEP folds the label's hash into the encoding, so a mismatched label decodes to
            // garbage padding — the token detects this and reports it as a decrypt failure.
            Assert.ThrowsAny<Pkcs11Exception>(() => session.Decrypt(Oaep(Encoding.UTF8.GetBytes("label-b")), priv, ciphertext));
        });
    }

    // pSourceData "must be NULL_PTR if the caller wants the default label" and ulSourceDataLen "must be 0" then
    // (PKCS#11 v3.2 §6.1.7): a NULL pSourceData behind ulSourceDataLen 8 is an invalid parameter, which
    // C_EncryptInit and C_DecryptInit refuse with CKR_MECHANISM_PARAM_INVALID, or CKR_ARGUMENTS_BAD for the NULL
    // pointer (§5.1.6), without reading through it. Through the raw dispatch, as the library's parameter type
    // cannot express it. After each refusal the same session encrypts (decrypts) with the empty label.
    internal static void Assert_OaepNullLabelWithLength_IsRefused(IPkcs11Backend backend)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("RSA-OAEP with a NULL label behind a length");
        WithRsaKeyPair(backend, (session, pub, priv) =>
        {
            byte[] ciphertext = OrSkipIfOaepHashUnsupported(() => session.Encrypt(Oaep([]), pub, plaintext));
            LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
            var sid = (NativeCULong)session.SessionId;
            var parameter = new CK_RSA_PKCS_OAEP_PARAMS
            {
                HashAlg = (NativeCULong)(ulong)CKM.CKM_SHA256,
                Mgf = (NativeCULong)(ulong)CKG.CKG_MGF1_SHA256,
                Source = (NativeCULong)CKZ.CKZ_DATA_SPECIFIED,
                SourceData = IntPtr.Zero,
                SourceDataLen = (NativeCULong)8UL,
            };
            Mechanism nullLabel = RawParameter.From(CKM.CKM_RSA_PKCS_OAEP, in parameter);
            foreach (bool encrypt in (bool[])[true, false])
            {
                string op = encrypt ? "C_EncryptInit" : "C_DecryptInit";
                CKR rv = RawInit(lowLevel, sid, encrypt, nullLabel, encrypt ? pub : priv);
                Assert.True(rv is CKR.CKR_MECHANISM_PARAM_INVALID or CKR.CKR_ARGUMENTS_BAD,
                    $"{op}(CKM_RSA_PKCS_OAEP) with a NULL pSourceData and ulSourceDataLen 8 returned {rv}.");
                byte[] input = encrypt ? session.Encrypt(Oaep([]), pub, plaintext) : ciphertext;
                Assert.Equal(plaintext, session.Decrypt(Oaep([]), priv, input));
            }
        });
    }

    private static CKR RawInit(LowLevelPkcs11Library lowLevel, NativeCULong sid, bool encrypt, Mechanism mechanism, ObjectHandle key)
    {
        using var scope = new MechanismParameterScope();
        CK_MECHANISM mech = mechanism.Marshal(scope, out _);
        return encrypt
            ? lowLevel.C_EncryptInit(sid, in mech, (NativeCULong)key.ObjectId)
            : lowLevel.C_DecryptInit(sid, in mech, (NativeCULong)key.ObjectId);
    }

    private static Mechanism Oaep(byte[] label) =>
        new(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, label));

    private static void WithRsaKeyPair(IPkcs11Backend backend, Action<Pkcs11SessionCore, ObjectHandle, ObjectHandle> body)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_PKCS_OAEP);
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
            try { body(session, pub, priv); }
            finally
            {
                session.DestroyObject(pub);
                session.DestroyObject(priv);
            }
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    // SoftHSM 2.5 (the softhsm-v240 CI leg's pinned Debian binary) advertises CKM_RSA_PKCS_OAEP but
    // only accepts CKM_SHA_1 as the hash parameter: SHA-256 fails at C_EncryptInit with
    // CKR_ARGUMENTS_BAD regardless of the label under test. Mirrors
    // RSAPkcs11TestCases.OrSkipIfOaepHashUnsupported's convention for this limitation.
    private static byte[] OrSkipIfOaepHashUnsupported(Func<byte[]> op)
    {
        try
        {
            return op();
        }
        catch (Pkcs11Exception ex) when (ex.ReturnValue is
            CKR.CKR_MECHANISM_PARAM_INVALID or CKR.CKR_MECHANISM_INVALID or
            CKR.CKR_ARGUMENTS_BAD or CKR.CKR_FUNCTION_NOT_SUPPORTED)
        {
            Assert.Skip("Token advertises OAEP but rejects this hash parameter.");
            throw; // Assert.Skip always throws; xunit.v3.assert 4.0.1 lacks [DoesNotReturn].
        }
    }
}
