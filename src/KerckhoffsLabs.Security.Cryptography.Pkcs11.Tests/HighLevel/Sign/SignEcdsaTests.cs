using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Sign;

/// <summary>
/// Shared test logic for ECDSA sign/verify round-trips across the NIST P-curves.
/// Requires real crypto — SoftHSM only; pkcs11-mock does not implement actual ECDSA.
/// </summary>
internal static class SignEcdsaTestCases
{
    internal static void Assert_Ecdsa_RoundTrip(IPkcs11Backend backend, byte[] ecParams, int expectedSigLen)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateEcKeyPair(session, ecParams);
            try
            {
                byte[] data = System.Text.Encoding.UTF8.GetBytes("phase-2 ECDSA round-trip");
                byte[] sig = session.SignEcdsa(priv, data);
                Assert.Equal(expectedSigLen, sig.Length); // r||s: 2 × curve-coordinate bytes

                session.VerifyEcdsa(pub, data, sig, out bool isValid);
                Assert.True(isValid, "ECDSA round-trip should verify.");
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
public sealed class SignEcdsaTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalTheory(nameof(SoftHsmAvailable))]
    [InlineData("P-256", 64)]
    [InlineData("P-384", 96)]
    [InlineData("P-521", 132)]
    public void Ecdsa_RoundTrip(string curve, int expectedSigLen)
        => SignEcdsaTestCases.Assert_Ecdsa_RoundTrip(_backend, TestKeys.EcParams(curve), expectedSigLen);
}
