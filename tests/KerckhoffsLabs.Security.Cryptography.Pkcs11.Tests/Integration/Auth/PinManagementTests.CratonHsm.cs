using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>
/// Craton HSM integration for <c>Pkcs11Session.SetPinWithPin</c> — performs a real <c>C_SetPIN</c>
/// round-trip and always restores the shared token's user PIN.
/// </summary>
[Collection("CratonHsm")]
[ResetCratonHsmLogin]
public sealed class PinManagementTests_CratonHsm(CratonHsmBackendFixture f)
{
    private readonly CratonHsmBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void SetPinWithPin_ChangesUserPin_RoundTrip()
    {
        byte[] original = _backend.UserPin.ToArray();
        byte[] temp = Encoding.UTF8.GetBytes("87654321");

        using var session = _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(original));

        bool atTemp = false;
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

        // Reaching here with atTemp == false proves both changes succeeded: the restoring SetPinWithPin
        // (temp -> original) only works if the first change actually took effect.
        Assert.False(atTemp);
    }
}
