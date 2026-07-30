using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These tests exercise the gated RSAES-PKCS#1 v1.5 / raw-RSA paths on purpose (the runtime
// AllowInsecure gate is the behaviour under test), so the compile-time warning is suppressed
// for this file only — the per-id suppression the diagnostic exists to enable.
#pragma warning disable KLPKCS11008

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Encrypt;

/// <summary>
/// The RSA PKCS#1 v1.5 encryption gate (backend-agnostic assertions; the per-backend test classes
/// live in <c>EncryptRsaTests.Pkcs11Mock.cs</c> and <c>EncryptRsaTests.SoftHsm2.cs</c>). RSA-OAEP
/// round-trips are covered by the RSAPkcs11 adapter tests
/// (<c>Integration/Adapters/RSAPkcs11Tests.EncryptDecrypt_OaepSha</c>).
/// </summary>
internal static class EncryptRsaTestCases
{
    internal static void Assert_RsaPkcs1V15_GatedByDefault(IPkcs11Backend backend)
    {
        // The InsecureOperationException guard fires before any P/Invoke call to C_Encrypt,
        // but a session must still be opened and a key pair generated first.
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
            try
            {
                byte[] plaintext = Encoding.UTF8.GetBytes("RSA v1.5 test");

                // CKM_RSA_PKCS (PKCS#1 v1.5) is gated by Session.GuardMechanism; the same gate the
                // RSAPkcs11.Encrypt(RSAEncryptionPadding.Pkcs1) path relies on.
                var mech = new Mechanism(CKM.CKM_RSA_PKCS);
                var ex = Assert.Throws<InsecureOperationException>(() =>
                    session.Encrypt(mech, pub, plaintext));
                Assert.Equal(CKM.CKM_RSA_PKCS, ex.Mechanism);
            }
            finally
            {
                session.DestroyObject(pub);
                session.DestroyObject(priv);
            }
        }
        finally
        {
            session.CloseSession();
        }
    }
}
