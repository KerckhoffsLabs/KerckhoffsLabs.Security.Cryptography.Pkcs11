using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Verify;

/// <summary>
/// Backend-agnostic assertions for the RSA PKCS#1 v1.5 verify gate. The per-backend test classes
/// live in <c>VerifyRsaPkcsTests.Pkcs11Mock.cs</c> and <c>VerifyRsaPkcsTests.SoftHsm2.cs</c>.
/// </summary>
internal static class VerifyRsaPkcsTestCases
{
    internal static void Assert_VerifyRsaPkcs1V15_GatedByDefault(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var fakeKey = new ObjectHandle(0);
            using var mech = new Mechanism(CKM.CKM_RSA_PKCS);
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.Verify(mech, fakeKey, Array.Empty<byte>(), Array.Empty<byte>(), out _));
            Assert.Equal(CKM.CKM_RSA_PKCS, ex.Mechanism);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}
