using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sessions;

/// <summary>
/// Verifies <see cref="Pkcs11Session.Dispose"/> logs the authenticated user out
/// (<c>C_Logout</c>) before closing the session, so the token's audit log records an explicit
/// logout — and that a failing logout never makes disposal throw.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class SessionDisposeTests
{
    private static (Pkcs11Library library, ManagedSoftToken token) NewLibrary()
    {
        var token = new ManagedSoftToken();
        return (token.Load(), token);
    }

    [Fact]
    public void Dispose_LogsOutBeforeClosingSession()
    {
        var (library, token) = NewLibrary();
        using (library)
        {
            var session = library.OpenSessionWithPin(
                ManagedSoftToken.TokenLabel, CKU.CKU_USER, new SecurePin("1234"));

            Assert.Equal(0, token.LogoutCallCount);

            session.Dispose();

            Assert.Equal(1, token.LogoutCallCount);
        }
    }

    [Fact]
    public void Dispose_SwallowsLogoutFailure_AndStillDisposes()
    {
        var (library, token) = NewLibrary();
        using (library)
        {
            var session = library.OpenSessionWithPin(
                ManagedSoftToken.TokenLabel, CKU.CKU_USER, new SecurePin("1234"));

            // Simulate "already logged out" — the canonical benign C_Logout failure.
            token.LogoutResult = CKR.CKR_USER_NOT_LOGGED_IN;

            // Disposal must not propagate the logout failure.
            session.Dispose();

            Assert.Equal(1, token.LogoutCallCount);
            // The session is disposed regardless of the logout outcome.
            Assert.Throws<ObjectDisposedException>(() => session.GenerateRandom(1));
        }
    }

    [Fact]
    public void Dispose_IsIdempotent_LogsOutOnce()
    {
        var (library, token) = NewLibrary();
        using (library)
        {
            var session = library.OpenSessionWithPin(
                ManagedSoftToken.TokenLabel, CKU.CKU_USER, new SecurePin("1234"));

            session.Dispose();
            session.Dispose();

            Assert.Equal(1, token.LogoutCallCount);
        }
    }
}
