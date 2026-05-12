using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

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
                Assert.NotNull(pub);
                Assert.NotNull(priv);
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

[Collection("SoftHsm")]
public sealed class GenerateEcKeyPairTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void GeneratesP256KeyPair() => GenerateEcKeyPairTestCases.Assert_GeneratesP256KeyPair(_backend);
}
