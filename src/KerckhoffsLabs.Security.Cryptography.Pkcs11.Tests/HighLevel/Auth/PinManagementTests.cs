using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Auth;

/// <summary>
/// Managed-side guards for the PIN-management surface (<c>Pkcs11Workspace.SetPin</c> /
/// <c>InitPin</c>). These fire before any P/Invoke, so they run on the mock and need no real
/// token — and crucially never change a PIN.
/// </summary>
[Collection("Mock")]
public sealed class PinManagementGuardTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    private Pkcs11Workspace OpenWorkspace() => _backend.Library.OpenWorkspace(
        _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact]
    public void SetPin_NullArgs_Throw()
    {
        using var ws = OpenWorkspace();
        using var pin = new SecurePin("12345"u8);
        Assert.Throws<ArgumentNullException>(() => ws.SetPin(null!, pin));
        Assert.Throws<ArgumentNullException>(() => ws.SetPin(pin, null!));
    }

    [Fact]
    public void InitPin_NullArg_Throws()
    {
        using var ws = OpenWorkspace();
        Assert.Throws<ArgumentNullException>(() => ws.InitPin(null!));
    }

    [Fact]
    public void PinManagement_AfterDispose_Throws()
    {
        var ws = OpenWorkspace();
        using var pin = new SecurePin("12345"u8);
        ws.Dispose();
        Assert.Throws<ObjectDisposedException>(() => ws.SetPin(pin, pin));
        Assert.Throws<ObjectDisposedException>(() => ws.InitPin(pin));
    }
}

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
        byte[] temp = System.Text.Encoding.UTF8.GetBytes("87654321");

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
    }
}
