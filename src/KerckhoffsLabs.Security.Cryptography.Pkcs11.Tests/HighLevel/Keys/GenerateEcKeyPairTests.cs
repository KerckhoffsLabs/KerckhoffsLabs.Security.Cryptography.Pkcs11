using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Keys;

internal static class GenerateEcKeyPairTestCases
{
    internal static void Assert_GeneratesP256KeyPair(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = session.GenerateEcKeyPair(curve: EcCurve.P256);
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

    internal static void Assert_RejectsInvalidCurve(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => session.GenerateEcKeyPair(curve: (EcCurve)99));
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("Mock")]
public sealed class GenerateEcKeyPairTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void RejectsInvalidCurve() => GenerateEcKeyPairTestCases.Assert_RejectsInvalidCurve(_backend);
}

[Collection("SoftHsm")]
public sealed class GenerateEcKeyPairTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GeneratesP256KeyPair() => GenerateEcKeyPairTestCases.Assert_GeneratesP256KeyPair(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RejectsInvalidCurve() => GenerateEcKeyPairTestCases.Assert_RejectsInvalidCurve(_backend);
}
