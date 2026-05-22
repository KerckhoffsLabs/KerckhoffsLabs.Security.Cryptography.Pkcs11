using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Sign;

/// <summary>
/// Shared test logic for EdDSA (Ed25519 and Ed448) sign/verify round-trips.
/// Requires real crypto — SoftHSM only; pkcs11-mock does not implement actual EdDSA.
/// </summary>
internal static class SignEdDsaTestCases
{
    internal static void Assert_Ed25519_RoundTrip(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateEd25519KeyPair(session);
            try
            {
                byte[] data = System.Text.Encoding.UTF8.GetBytes("phase-2 Ed25519 round-trip");
                byte[] sig = session.SignEd25519(priv, data);
                Assert.Equal(64, sig.Length);

                session.VerifyEd25519(pub, data, sig, out bool isValid);
                Assert.True(isValid, "Ed25519 round-trip should verify.");
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

    internal static void Assert_Ed448_RoundTrip(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateEd448KeyPair(session);
            try
            {
                byte[] data = System.Text.Encoding.UTF8.GetBytes("phase-2 Ed448 round-trip");
                byte[] sig = session.SignEd448(priv, data);
                Assert.Equal(114, sig.Length);

                session.VerifyEd448(pub, data, sig, out bool isValid);
                Assert.True(isValid, "Ed448 round-trip should verify.");
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
public sealed class SignEdDsaTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ed25519_RoundTrip() => SignEdDsaTestCases.Assert_Ed25519_RoundTrip(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ed448_RoundTrip() => SignEdDsaTestCases.Assert_Ed448_RoundTrip(_backend);
}
