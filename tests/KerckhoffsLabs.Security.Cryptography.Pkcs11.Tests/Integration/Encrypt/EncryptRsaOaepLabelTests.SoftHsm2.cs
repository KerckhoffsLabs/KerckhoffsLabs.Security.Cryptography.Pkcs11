using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>
/// Drives <see cref="CkmRsaPkcsOaepParams"/>'s optional encoding-parameter source data (the
/// <c>CKZ_DATA_SPECIFIED</c> label, PKCS#1 v2.2 §7.1) against a real token — every other RSA-OAEP
/// test in this suite (via <c>RSAPkcs11</c> / <c>Pkcs11MechanismMap.RsaOaep</c>) passes an empty
/// label. SoftHSM2's <c>OSSLRSA.cpp</c> feeds the label into
/// <c>EVP_PKEY_CTX_set0_rsa_oaep_label</c> for both encrypt and decrypt (verified against
/// <c>vendor/softhsmv2/src/lib/crypto/OSSLRSA.cpp</c>), so it is genuinely part of the OAEP encoding
/// rather than merely validated and discarded — decrypting with the wrong label must fail exactly
/// like decrypting with the wrong key would.
/// </summary>
[Collection("SoftHsm")]
public sealed class EncryptRsaOaepLabelTests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;

    // SoftHSM 2.5 (the softhsm-v240 CI leg's pinned Debian binary) advertises CKM_RSA_PKCS_OAEP but
    // only actually accepts CKM_SHA_1 as the hash parameter — SHA-256 fails at C_EncryptInit with
    // CKR_ARGUMENTS_BAD regardless of the label under test here. Mirrors
    // RSAPkcs11TestCases.OrSkipIfOaepHashUnsupported's existing convention for this exact limitation.
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

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void OaepWithLabel_RoundTrips()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
            try
            {
                byte[] plaintext = Encoding.UTF8.GetBytes("RSA-OAEP with an encoding-parameter label");
                byte[] label = Encoding.UTF8.GetBytes("invoice-2026-09");

                var encryptMech = new Mechanism(CKM.CKM_RSA_PKCS_OAEP,
                    new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, label));
                byte[] ciphertext = OrSkipIfOaepHashUnsupported(() => session.Encrypt(encryptMech, pub, plaintext));

                var decryptMech = new Mechanism(CKM.CKM_RSA_PKCS_OAEP,
                    new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, label));
                byte[] recovered = session.Decrypt(decryptMech, priv, ciphertext);

                Assert.Equal(plaintext, recovered);
            }
            finally
            {
                session.DestroyObject(pub);
                session.DestroyObject(priv);
            }
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.Dispose();
        }
    }

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void OaepWithWrongLabel_FailsToDecrypt()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
            try
            {
                byte[] plaintext = Encoding.UTF8.GetBytes("RSA-OAEP label mismatch must fail");

                var encryptMech = new Mechanism(CKM.CKM_RSA_PKCS_OAEP,
                    new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, Encoding.UTF8.GetBytes("label-a")));
                byte[] ciphertext = OrSkipIfOaepHashUnsupported(() => session.Encrypt(encryptMech, pub, plaintext));

                var decryptMech = new Mechanism(CKM.CKM_RSA_PKCS_OAEP,
                    new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, Encoding.UTF8.GetBytes("label-b")));

                // OAEP folds the label's hash into the encoding, so a mismatched label decodes to
                // garbage padding — the token detects this and reports it as a decrypt failure.
                Assert.ThrowsAny<Pkcs11Exception>(() => session.Decrypt(decryptMech, priv, ciphertext));
            }
            finally
            {
                session.DestroyObject(pub);
                session.DestroyObject(priv);
            }
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.Dispose();
        }
    }
}
