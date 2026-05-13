using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Sign;

/// <summary>
/// Shared test logic for ECDSA P-256 sign/verify round-trip.
/// Requires real crypto — SoftHSM only; pkcs11-mock does not implement actual ECDSA.
/// </summary>
internal static class SignEcdsaTestCases
{
    internal static void Assert_Ecdsa_RoundTrip(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
            try
            {
                byte[] data = System.Text.Encoding.UTF8.GetBytes("phase-2 ECDSA round-trip");
                byte[] sig = session.SignEcdsa(priv, data);
                Assert.Equal(64, sig.Length); // 2 × 32-byte P-256 coordinates

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

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ecdsa_RoundTrip() => SignEcdsaTestCases.Assert_Ecdsa_RoundTrip(_backend);
}
