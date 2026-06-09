using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>
/// SoftHSM-only integration for <c>Pkcs11Workspace.SetPin</c> — performs a real <c>C_SetPIN</c>
/// round-trip and always restores the shared token's user PIN.
/// </summary>
[Collection("SoftHsm")]
public sealed class PinManagementTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void SetPin_ChangesUserPin_RoundTrip()
    {
        byte[] original = _backend.UserPin.ToArray();
        byte[] temp = Encoding.UTF8.GetBytes("87654321");

        using var workspace = _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(original));

        bool atTemp = false;
        try
        {
            using (var o = new SecurePin(original))
            using (var n = new SecurePin(temp))
                workspace.SetPin(o, n);
            atTemp = true;

            // Succeeds only if the PIN is now 'temp' — which proves the first change took effect —
            // and restores the shared token's PIN to its original value.
            using (var o = new SecurePin(temp))
            using (var n = new SecurePin(original))
                workspace.SetPin(o, n);
            atTemp = false;
        }
        finally
        {
            if (atTemp)
            {
                using var o = new SecurePin(temp);
                using var n = new SecurePin(original);
                try { workspace.SetPin(o, n); } catch { /* best-effort restore of shared token */ }
            }
        }

        // Reaching here with atTemp == false proves both changes succeeded: the restoring SetPin
        // (temp -> original) only works if the first change actually took effect.
        Assert.False(atTemp);
    }
}
