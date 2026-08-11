using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Workspace;

/// <summary>
/// Verifies <see cref="Pkcs11Workspace.Dispose"/> logs the authenticated user out
/// (<c>C_Logout</c>) before closing the session, so the token's audit log records an explicit
/// logout — and that a failing logout never makes disposal throw.
/// </summary>
[NoBackendCollection("Drives a per-test ManagedSoftToken in process — no native module is loaded and " +
                     "the token holds no static state, so this is safe alongside every backend collection.")]
public sealed class WorkspaceDisposeTests
{
    private static (Pkcs11Library library, ManagedSoftToken token) NewLibrary()
    {
        var token = new ManagedSoftToken();
        return (new Pkcs11Library(token), token);
    }

    [Fact]
    public void Dispose_LogsOutBeforeClosingSession()
    {
        var (library, token) = NewLibrary();
        using (library)
        {
            var workspace = library.OpenWorkspace(
                ManagedSoftToken.TokenLabel, CKU.CKU_USER, new SecurePin("1234"));

            Assert.Equal(0, token.LogoutCallCount);

            workspace.Dispose();

            Assert.Equal(1, token.LogoutCallCount);
        }
    }

    [Fact]
    public void Dispose_SwallowsLogoutFailure_AndStillDisposes()
    {
        var (library, token) = NewLibrary();
        using (library)
        {
            var workspace = library.OpenWorkspace(
                ManagedSoftToken.TokenLabel, CKU.CKU_USER, new SecurePin("1234"));

            // Simulate "already logged out" — the canonical benign C_Logout failure.
            token.LogoutResult = CKR.CKR_USER_NOT_LOGGED_IN;

            // Disposal must not propagate the logout failure.
            workspace.Dispose();

            Assert.Equal(1, token.LogoutCallCount);
            // The workspace is disposed regardless of the logout outcome.
            Assert.Throws<ObjectDisposedException>(() => workspace.GenerateRandom(1));
        }
    }

    [Fact]
    public void Dispose_IsIdempotent_LogsOutOnce()
    {
        var (library, token) = NewLibrary();
        using (library)
        {
            var workspace = library.OpenWorkspace(
                ManagedSoftToken.TokenLabel, CKU.CKU_USER, new SecurePin("1234"));

            workspace.Dispose();
            workspace.Dispose();

            Assert.Equal(1, token.LogoutCallCount);
        }
    }
}
