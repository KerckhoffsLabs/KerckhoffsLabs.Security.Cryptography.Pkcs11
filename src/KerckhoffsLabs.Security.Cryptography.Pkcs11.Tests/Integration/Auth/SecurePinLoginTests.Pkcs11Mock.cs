using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>
/// Shared test logic for SecurePin Login overloads. Runs against pkcs11-mock only
/// (no real crypto needed — just a successful login/logout round-trip and a null guard).
/// </summary>
internal static class SecurePinLoginTestCases
{
    internal static void Assert_Login_AcceptsSecurePin(IPkcs11Backend backend)
    {
        var slot = backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == backend.SlotId);
        var session = slot.OpenSession();
        try
        {
            using var pin = new SecurePin(backend.UserPin.Span);
            session.Login(CKU.CKU_USER, pin);
            session.Logout();
        }
        finally
        {
            session.CloseSession();
        }
    }

    internal static void Assert_Login_RejectsNullSecurePin(IPkcs11Backend backend)
    {
        var slot = backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == backend.SlotId);
        var session = slot.OpenSession();
        try
        {
            Assert.Throws<ArgumentNullException>(() => session.Login(CKU.CKU_USER, (SecurePin)null!));
        }
        finally
        {
            session.CloseSession();
        }
    }
}

[Collection("Mock")]
public sealed class SecurePinLoginTests_Mock(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact] public void Login_AcceptsSecurePin() => SecurePinLoginTestCases.Assert_Login_AcceptsSecurePin(_backend);
    [Fact] public void Login_RejectsNullSecurePin() => SecurePinLoginTestCases.Assert_Login_RejectsNullSecurePin(_backend);
}
