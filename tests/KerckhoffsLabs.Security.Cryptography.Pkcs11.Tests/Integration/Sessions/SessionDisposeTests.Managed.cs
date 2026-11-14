using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sessions;

/// <summary>
/// Verifies that disposing a <see cref="Pkcs11Session"/> logs the token out (<c>C_Logout</c>) only when the
/// session was the last holder of its <see cref="Pkcs11Login"/>, so the token's audit log records an explicit
/// logout at the end of the login; that a session without a login never logs out; and that a failing logout
/// never makes disposal throw.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class SessionDisposeTests
{
    private static (Pkcs11Library library, ManagedSoftToken token) NewLibrary()
    {
        var token = new ManagedSoftToken();
        return (token.Load(), token);
    }

    private static Pkcs11Login LogIn(Pkcs11Library library)
    {
        using var pin = new SecurePin("1234");
        return library.GetSlotByTokenLabel(ManagedSoftToken.TokenLabel).Login(TokenUser.User, pin);
    }

    [Fact]
    public void Dispose_OfTheLastHolder_LogsOut()
    {
        var (library, token) = NewLibrary();
        using (library)
        {
            using Pkcs11Login login = LogIn(library);
            using Pkcs11Session session = login.OpenSession();

            login.Dispose();
            Assert.Equal(0, token.LogoutCallCount); // the session still holds the login

            session.Dispose();
            Assert.Equal(1, token.LogoutCallCount);
        }
    }

    [Fact]
    public void Dispose_OfASessionWithoutALogin_NeverLogsOut()
    {
        var (library, token) = NewLibrary();
        using (library)
        {
            using Pkcs11Login login = LogIn(library);
            using Pkcs11Session session = library.GetSlotByTokenLabel(ManagedSoftToken.TokenLabel).OpenSession();

            session.Dispose();

            Assert.Equal(0, token.LogoutCallCount);
        }
    }

    [Fact]
    public void Dispose_SwallowsLogoutFailure_AndStillDisposes()
    {
        var (library, token) = NewLibrary();
        using (library)
        {
            Pkcs11Session session;
            using (Pkcs11Login login = LogIn(library))
                session = login.OpenSession();

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
            Pkcs11Session session;
            using (Pkcs11Login login = LogIn(library))
                session = login.OpenSession();

            session.Dispose();
            session.Dispose();

            Assert.Equal(1, token.LogoutCallCount);
        }
    }
}
