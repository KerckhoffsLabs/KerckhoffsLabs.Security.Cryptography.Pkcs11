using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Sign;

/// <summary>
/// Shared test logic for RSA-PSS sign/verify round-trip.
/// Requires real crypto — SoftHSM only; pkcs11-mock does not implement actual PSS.
/// </summary>
internal static class SignRsaPssTestCases
{
    /// <summary>SoftHSM-only round trip: generate signing key, sign with PSS, verify, assert valid.</summary>
    internal static void Assert_RsaPss_RoundTrip(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateRsa2048SigningKeyPair(session);
            try
            {
                byte[] data = System.Text.Encoding.UTF8.GetBytes("phase-2 PSS round-trip");
                byte[] sig = session.SignRsaPss(priv, data);
                Assert.Equal(256, sig.Length); // 2048 bits / 8

                session.VerifyRsaPss(pub, data, sig, out bool isValid);
                Assert.True(isValid, "RSA-PSS round-trip should verify.");
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

// ---------------------------------------------------------------------------
// Concrete test class: SoftHSM backend only (real crypto required)
// ---------------------------------------------------------------------------

[Collection("SoftHsm")]
public sealed class SignRsaPssTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void RsaPss_RoundTrip() => SignRsaPssTestCases.Assert_RsaPss_RoundTrip(_backend);
}
