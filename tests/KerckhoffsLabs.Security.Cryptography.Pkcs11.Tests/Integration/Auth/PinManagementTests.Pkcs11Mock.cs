using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>
/// Managed-side guards for <c>Pkcs11Session.SetPinWithPin</c>. These fire before any P/Invoke, so they run on
/// the mock and need no real token — and crucially never change a PIN. <c>Pkcs11Login.InitUserPinWithPin</c>
/// needs an SO login, which the mock's single session leaves no room for; its guards run over
/// <c>LoginTokenModule</c> (Unit/PinManagementTests).
/// </summary>
[Collection("Mock")]
public sealed class PinManagementGuardTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    private Pkcs11Session OpenSession() => _backend.OpenSession();

    [Fact]
    public void SetPinWithPin_NullArgs_Throw()
    {
        using var ws = OpenSession();
        using var pin = new SecurePin("12345"u8);
        Assert.Throws<ArgumentNullException>(() => ws.SetPinWithPin(null!, pin));
        Assert.Throws<ArgumentNullException>(() => ws.SetPinWithPin(pin, null!));
    }

    [Fact]
    public void PinManagement_AfterDispose_Throws()
    {
        var ws = OpenSession();
        using var pin = new SecurePin("12345"u8);
        ws.Dispose();
        Assert.Throws<ObjectDisposedException>(() => ws.SetPinWithPin(pin, pin));
    }
}
