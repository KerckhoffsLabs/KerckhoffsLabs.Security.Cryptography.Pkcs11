using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Decrypt;

/// <summary>
/// The RSA PKCS#1 v1.5 decryption gate (backend-agnostic assertions; the per-backend test
/// classes live in <c>DecryptRsaTests.Pkcs11Mock.cs</c> and <c>DecryptRsaTests.SoftHsm2.cs</c>).
/// RSA-OAEP round-trips are covered by the RSAPkcs11 adapter tests
/// (<c>Integration/Adapters/RSAPkcs11Tests.EncryptDecrypt_OaepSha</c>).
/// </summary>
internal static class DecryptRsaTestCases
{
    /// <summary>
    /// RSA PKCS#1 v1.5 decryption (CKM_RSA_PKCS) must throw <see cref="InsecureOperationException"/>
    /// by default. The gate fires before C_DecryptInit, so only a session (no real key) is needed.
    /// </summary>
    internal static void Assert_RsaPkcs1V15_GatedByDefault(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateRsa2048KeyPair(session);
            try
            {
                byte[] fakeCiphertext = new byte[256]; // RSA-2048 output size

                // CKM_RSA_PKCS (PKCS#1 v1.5) is gated by Session.GuardMechanism; the same gate the
                // RSAPkcs11.Decrypt(RSAEncryptionPadding.Pkcs1) path relies on.
                using var mech = new Mechanism(CKM.CKM_RSA_PKCS);
                var ex = Assert.Throws<InsecureOperationException>(() =>
                    session.Decrypt(mech, priv, fakeCiphertext));
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
