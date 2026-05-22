using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

internal static class GenerateRsaKeyPairTestCases
{
    internal static void Assert_RejectsTooSmallModulus(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => session.GenerateRsaKeyPair(modulusBits: 1024));
            Assert.Throws<ArgumentOutOfRangeException>(() => session.GenerateRsaKeyPair(modulusBits: 0));
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }

    internal static void Assert_GeneratesRsa2048KeyPair(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = session.GenerateRsaKeyPair(modulusBits: 2048);
            try
            {
                Assert.NotEqual(0UL, pub.ObjectId);
                Assert.NotEqual(0UL, priv.ObjectId);
            }
            finally
            {
                session.DestroyObject(priv);
                session.DestroyObject(pub);
            }
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("Mock")]
public sealed class GenerateRsaKeyPairTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void RejectsTooSmallModulus() => GenerateRsaKeyPairTestCases.Assert_RejectsTooSmallModulus(_backend);
}

[Collection("SoftHsm")]
public sealed class GenerateRsaKeyPairTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsTooSmallModulus() => GenerateRsaKeyPairTestCases.Assert_RejectsTooSmallModulus(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GeneratesRsa2048KeyPair() => GenerateRsaKeyPairTestCases.Assert_GeneratesRsa2048KeyPair(_backend);
}
