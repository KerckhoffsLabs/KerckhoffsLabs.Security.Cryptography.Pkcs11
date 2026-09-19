using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>
/// Managed-side guards for the PIN-management surface (<c>Pkcs11Workspace.SetPinWithPin</c> /
/// <c>InitPinWithPin</c>). These fire before any P/Invoke, so they run on the mock and need no real
/// token — and crucially never change a PIN.
/// </summary>
[Collection("Mock")]
public sealed class PinManagementGuardTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    private Pkcs11Workspace OpenWorkspace() => _backend.Library.OpenWorkspaceWithPin(
        _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    [Fact]
    public void SetPinWithPin_NullArgs_Throw()
    {
        using var ws = OpenWorkspace();
        using var pin = new SecurePin("12345"u8);
        Assert.Throws<ArgumentNullException>(() => ws.SetPinWithPin(null!, pin));
        Assert.Throws<ArgumentNullException>(() => ws.SetPinWithPin(pin, null!));
    }

    [Fact]
    public void InitPinWithPin_NullArg_Throws()
    {
        using var ws = OpenWorkspace();
        Assert.Throws<ArgumentNullException>(() => ws.InitPinWithPin(null!));
    }

    [Fact]
    public void PinManagement_AfterDispose_Throws()
    {
        var ws = OpenWorkspace();
        using var pin = new SecurePin("12345"u8);
        ws.Dispose();
        Assert.Throws<ObjectDisposedException>(() => ws.SetPinWithPin(pin, pin));
        Assert.Throws<ObjectDisposedException>(() => ws.InitPinWithPin(pin));
    }
}
