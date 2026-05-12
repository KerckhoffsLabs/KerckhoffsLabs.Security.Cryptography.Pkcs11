using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Verify;

internal static class VerifyRsaPkcsTestCases
{
    internal static void Assert_VerifyRsaPkcs1V15_GatedByDefault(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var fakeKey = new ObjectHandle(0);
#pragma warning disable CS0618
            var ex = Assert.Throws<InsecureOperationException>(() =>
                session.VerifyRsaPkcs1V15(fakeKey, Array.Empty<byte>(), Array.Empty<byte>(), out _));
#pragma warning restore CS0618
            Assert.Equal(CKM.CKM_RSA_PKCS, ex.Mechanism);
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("Mock")]
public sealed class VerifyRsaPkcsTests_Mock
{
    private readonly MockBackendFixture _backend;
    public VerifyRsaPkcsTests_Mock(MockBackendFixture f) { _backend = f; }

    [Fact]
    public void VerifyRsaPkcs1V15_GatedByDefault() => VerifyRsaPkcsTestCases.Assert_VerifyRsaPkcs1V15_GatedByDefault(_backend);
}

[Collection("SoftHsm")]
public sealed class VerifyRsaPkcsTests_SoftHsm
{
    private readonly SoftHsmBackendFixture _backend;
    public VerifyRsaPkcsTests_SoftHsm(SoftHsmBackendFixture f) { _backend = f; }
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void VerifyRsaPkcs1V15_GatedByDefault() => VerifyRsaPkcsTestCases.Assert_VerifyRsaPkcs1V15_GatedByDefault(_backend);
}
