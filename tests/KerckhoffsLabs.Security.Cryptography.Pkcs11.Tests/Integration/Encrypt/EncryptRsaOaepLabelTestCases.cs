using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
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

    private static Mechanism Oaep(byte[] label) =>
        new(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, label));

    private static void WithRsaKeyPair(IPkcs11Backend backend, Action<Pkcs11SessionCore, ObjectHandle, ObjectHandle> body)
    {
        backend.RequireMechanisms(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKM.CKM_RSA_PKCS_OAEP);
        var session = TestKeys.OpenLoggedInSession(backend);
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
            session.Dispose();
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
