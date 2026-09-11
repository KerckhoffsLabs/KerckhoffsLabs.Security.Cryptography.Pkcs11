using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Shared test logic for EdDSA (Ed25519 and Ed448) sign/verify round-trips.
/// Requires real crypto — SoftHSM only; pkcs11-mock does not implement actual EdDSA.
/// </summary>
internal static class SignEdDsaTestCases
{
    internal static void Assert_Ed25519_RoundTrip(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_EDDSA);
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateEd25519KeyPair(session);
            try
            {
                byte[] data = Encoding.UTF8.GetBytes("phase-2 Ed25519 round-trip");
                var eddsa = new Mechanism(CKM.CKM_EDDSA);
                byte[] sig = session.Sign(eddsa, priv, data);
                Assert.Equal(64, sig.Length);

                session.Verify(eddsa, pub, data, sig, out bool isValid);
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
            TestKeys.LogoutIfRequired(backend, session);
            session.CloseSession();
        }
    }

    internal static void Assert_Ed448_RoundTrip(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_EDDSA);
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateEd448KeyPair(session);
            try
            {
                byte[] data = Encoding.UTF8.GetBytes("phase-2 Ed448 round-trip");
                // Unlike Ed25519, a bare CKM_EDDSA (no CK_EDDSA_PARAMS) is not universally
                // accepted for Ed448 — Kryoptic, opencryptoki, and NSS all require an explicit
                // CK_EDDSA_PARAMS to pick pure Ed448 over Ed448ph, and return
                // CKR_MECHANISM_PARAM_INVALID for a bare mechanism. Pass one explicitly
                // (phFlag: false selects pure Ed448, no context data) so this works everywhere.
                var eddsa = new Mechanism(CKM.CKM_EDDSA, new CkmEddsaParams(phFlag: false));
                byte[] sig = session.Sign(eddsa, priv, data);
                Assert.Equal(114, sig.Length);

                session.Verify(eddsa, pub, data, sig, out bool isValid);
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
            TestKeys.LogoutIfRequired(backend, session);
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
