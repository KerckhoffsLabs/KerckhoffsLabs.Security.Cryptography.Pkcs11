using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11Slot.OpenLoggedInSession"/>: share or log in, open a session under the login, and leave the session
/// as what keeps it.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class OpenLoggedInSessionTests : IDisposable
{
    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;

    public OpenLoggedInSessionTests() => _library = _module.Load();

    public void Dispose()
    {
        _library.Dispose();
        _module.Dispose();
    }

    private Pkcs11Slot Slot => Assert.Single(_library.GetSlotList());

    private LoginCredential FromSecretStore(Action? asked = null) => LoginCredential.FromPinSource(() =>
    {
        asked?.Invoke();
        return new SecurePin(_module.ExpectedPin);
    });

    [Fact]
    public void LogsIn_AndTheSessionIsWhatKeepsTheLogin()
    {
        Pkcs11Session session = Slot.OpenLoggedInSession(FromSecretStore());

        Assert.Equal(1, _module.LoginCalls);
        Assert.Equal(TokenUser.User, session.LoginInfo!.User);
        Assert.True(session.LoginInfo.IsActive);
        Assert.Equal(SessionAccess.ReadWrite, session.Access);
        Assert.Equal(0, _module.LogoutCalls);

        session.Dispose();

        Assert.Equal(1, _module.LogoutCalls);
    }

    // A second call shares the login the first session keeps, without asking for the PIN.
    [Fact]
    public void ASecondCall_SharesTheLogin()
    {
        int asked = 0;
        using Pkcs11Session first = Slot.OpenLoggedInSession(FromSecretStore(() => asked++));
        using Pkcs11Session second = Slot.OpenLoggedInSession(FromSecretStore(() => asked++));

        Assert.Equal(1, asked);
        Assert.Equal(1, _module.LoginCalls);
        Assert.True(second.LoginInfo!.IsActive);
    }

    [Fact]
    public void TheLoginStaysUntilTheLastSessionGoes()
    {
        Pkcs11Session first = Slot.OpenLoggedInSession(FromSecretStore());
        Pkcs11Session second = Slot.OpenLoggedInSession(FromSecretStore());

        first.Dispose();
        Assert.Equal(0, _module.LogoutCalls);

        second.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
    }

    [Fact]
    public void TheAccessAskedFor_IsTheSessionsExactly()
    {
        using Pkcs11Session session = Slot.OpenLoggedInSession(FromSecretStore(), SessionAccess.ReadOnly);

        Assert.Equal(SessionAccess.ReadOnly, session.Access);
    }

    [Fact]
    public void TheUsernameAndPolicy_ReachTheLoginAndTheSession()
    {
        using Pkcs11Session session = Slot.OpenLoggedInSession(
            FromSecretStore(), username: "alice", policy: CryptoPolicy.NistApproved);

        Assert.Equal("alice", session.LoginInfo!.Username);
        Assert.Same(CryptoPolicy.NistApproved, session.Policy);
    }

    // The login this call made goes with the session that could not open, so nothing keeps the token logged in.
    [Fact]
    public void TheSessionCannotOpen_TheLoginItMadeIsLoggedOut()
    {
        _module.GrantsReadOnlyOnly = true;

        Assert.ThrowsAny<Pkcs11Exception>(() => Slot.OpenLoggedInSession(FromSecretStore(), SessionAccess.ReadWrite));

        Assert.Equal(1, _module.LoginCalls);
        Assert.Equal(1, _module.LogoutCalls);
        Assert.False(Slot.TryShareLogin(out _));
    }

    [Fact]
    public void RefusesANullCredential_AnUndefinedAccess_AndAnEmptyUsername_BeforeTheModule()
    {
        Assert.Throws<ArgumentNullException>(() => Slot.OpenLoggedInSession(null!));
        var undefined = Assert.Throws<ArgumentOutOfRangeException>(() => Slot.OpenLoggedInSession(FromSecretStore(), (SessionAccess)42));
        Assert.Equal("access", undefined.ParamName);
        Assert.Throws<ArgumentException>(() => Slot.OpenLoggedInSession(FromSecretStore(), username: ""));

        Assert.Equal(0, _module.LoginCalls);
    }
}
