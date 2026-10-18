using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

internal static class VerifyEdDsaTestCases
{
    internal static void Assert_Ed25519_RejectsTamperedData(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_EDDSA);
        using var session = TestKeys.OpenLoggedInSession(backend);
        var (pub, priv) = TestKeys.GenerateEd25519KeyPair(session);
        try
        {
            byte[] data = Encoding.UTF8.GetBytes("Ed25519 tamper");
            var eddsa = new Mechanism(CKM.CKM_EDDSA);
            byte[] sig = session.Sign(eddsa, priv, data);
            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;

            bool isValid = session.Verify(eddsa, pub, tampered, sig);
            Assert.False(isValid, "Tampered data must not verify.");
        }
        finally
        {
            session.DestroyObject(priv);
            session.DestroyObject(pub);
            TestKeys.LogoutIfRequired(backend, session);
        }
    }
}
