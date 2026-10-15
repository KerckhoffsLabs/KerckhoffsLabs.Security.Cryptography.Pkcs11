using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Digest;

/// <summary>
/// Shared test logic for SHA-2 digest operations.
/// Real backends only: pkcs11-mock returns canned data rather than computing real SHA-x,
/// so known-answer and output-length tests are unreliable on the mock backend.
/// </summary>
internal static class DigestSha2TestCases
{
    /// <summary>Real SHA-256 over "abc" matches the published test vector.</summary>
    internal static void Assert_Sha256_KnownAnswer(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            byte[] data = Encoding.UTF8.GetBytes("abc");
            var mech = new Mechanism(CKM.CKM_SHA256);
            byte[] digest = session.Digest(mech, data);
            Assert.Equal(32, digest.Length);

            // NIST FIPS 180-4 published vector for SHA-256("abc"):
            // BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
            byte[] expected = Convert.FromHexString("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
            Assert.Equal(expected, digest);
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    internal static void Assert_Sha384_OutputLength(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var mech = new Mechanism(CKM.CKM_SHA384);
            byte[] digest = session.Digest(mech, Encoding.UTF8.GetBytes("phase-3"));
            Assert.Equal(48, digest.Length);
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    internal static void Assert_Sha512_OutputLength(IPkcs11Backend backend)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var mech = new Mechanism(CKM.CKM_SHA512);
            byte[] digest = session.Digest(mech, Encoding.UTF8.GetBytes("phase-3"));
            Assert.Equal(64, digest.Length);
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
        }
    }
}
