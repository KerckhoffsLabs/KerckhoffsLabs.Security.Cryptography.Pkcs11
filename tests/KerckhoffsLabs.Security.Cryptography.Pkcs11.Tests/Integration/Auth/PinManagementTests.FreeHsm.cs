using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>
/// FreeHSM integration for <c>Pkcs11Session.SetPinWithPin</c> — performs a real <c>C_SetPIN</c> round-trip and always
/// restores the shared token's user PIN. Before 2.8.0 FreeHSM's <c>C_SetPIN</c> could change no PIN: it verified the old
/// PIN through its login path, which answered <c>CKR_USER_ALREADY_LOGGED_IN</c> (afchine1337/freehsm#36).
/// </summary>
[Collection("FreeHsm")]
public sealed class PinManagementTests_FreeHsm(FreeHsmBackendFixture f)
{
    private readonly FreeHsmBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void SetPinWithPin_ChangesUserPin_RoundTrip()
    {
        byte[] original = _backend.UserPin.ToArray();
        byte[] temp = Encoding.UTF8.GetBytes("87654321");

        bool atTemp = false;
        using (var session = _backend.OpenSession())
        {
            try
            {
                using (var o = new SecurePin(original))
                using (var n = new SecurePin(temp))
                    session.SetPinWithPin(o, n);
                atTemp = true;

                // Succeeds only if the PIN is now 'temp' — which proves the first change took effect —
                // and restores the shared token's PIN to its original value.
                using (var o = new SecurePin(temp))
                using (var n = new SecurePin(original))
                    session.SetPinWithPin(o, n);
                atTemp = false;
            }
            finally
            {
                if (atTemp)
                {
                    using var o = new SecurePin(temp);
                    using var n = new SecurePin(original);
                    try { session.SetPinWithPin(o, n); } catch (Pkcs11Exception) { /* best-effort restore of shared token */ }
                }
            }
        }

        Assert.False(atTemp);

        // The original PIN logs in again.
        using var again = _backend.OpenSession();
    }
}
