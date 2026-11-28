using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Costs;

/// <summary>
/// The native calls the login model costs (#365): a login is the token's, held on an anchor session the library opens
/// for it, and shared by every session opened under it; the last holder's release logs out. A cold login therefore
/// costs more round trips than a session that logs in on itself, and a warm one sends no login at all.
/// </summary>
/// <remarks>
/// The slot is selected by token label, so a login and a share re-read the token's identity to refuse a token swapped
/// in since (<c>C_GetTokenInfo</c>). These pins record today's costs, so a change to the login path states its effect
/// by updating them. They do not pin the order of the calls; the comments give it.
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class LoginCallCountTests : IDisposable
{
    private static readonly LoginCredential Pin = LoginCredential.FromPinSource(() => new SecurePin("1234"));

    private readonly ManagedSoftToken _token = new();
    private readonly Pkcs11Library _library;
    private readonly Pkcs11Slot _slot;

    public LoginCallCountTests()
    {
        _library = _token.Load();
        _slot = _library.GetSlotByTokenLabel(ManagedSoftToken.TokenLabel);
    }

    public void Dispose() => _library.Dispose();

    // The slot list (a count, then the ids) and the token in the one slot.
    [Fact]
    public void GetSlotByTokenLabel()
        => Assert.Equal("C_GetSlotList×2, C_GetTokenInfo×1",
            NativeCalls.Of(_token, () => _library.GetSlotByTokenLabel(ManagedSoftToken.TokenLabel)));

    // With no login held: the token re-read before the PIN source runs; the anchor session opened, and its access
    // checked (C_GetSessionInfo: the module may grant read-only); the token re-read now the anchor is open; the token
    // read for the PIN's scope; C_Login; the probe that the anchor is logged in (C_GetSessionInfo); then the caller's
    // session opened and its access checked. On Dispose, the session closes, and as the last holder it logs out on the
    // anchor and closes it.
    [Fact]
    public void OpenLoggedInSession_Cold_ThenDispose()
        => Assert.Equal(
            "C_CloseSession×2, C_GetSessionInfo×3, C_GetTokenInfo×3, C_Login×1, C_Logout×1, C_OpenSession×2",
            NativeCalls.Of(_token, () => _slot.OpenLoggedInSession(Pin).Dispose()));

    // The anchor opened and checked, the token re-read, the token read for the PIN's scope, C_Login, the probe.
    [Fact]
    public void Login_Cold()
    {
        Pkcs11Login? login = null;
        string calls = NativeCalls.Of(_token, () => login = _slot.Login(TokenUser.User, Pin));
        using (login)
            Assert.Equal("C_GetSessionInfo×2, C_GetTokenInfo×2, C_Login×1, C_OpenSession×1", calls);
    }

    // The last holder's release: C_Logout on the anchor, which then closes.
    [Fact]
    public void Login_Dispose_AsTheLastHolder()
    {
        Pkcs11Login login = _slot.Login(TokenUser.User, Pin);

        Assert.Equal("C_CloseSession×1, C_Logout×1", NativeCalls.Of(_token, login.Dispose));
    }

    // With a login held elsewhere: the probe of the anchor, the token re-read, then the session opened, checked and
    // closed. No C_Login and no C_Logout.
    [Fact]
    public void OpenLoggedInSession_Warm_ThenDispose()
    {
        using Pkcs11Login held = _slot.Login(TokenUser.User, Pin);

        Assert.Equal("C_CloseSession×1, C_GetSessionInfo×2, C_GetTokenInfo×1, C_OpenSession×1",
            NativeCalls.Of(_token, () => _slot.OpenLoggedInSession(Pin).Dispose()));
    }

    // The probe of the anchor and the token re-read; the share's release does not log out.
    [Fact]
    public void ShareOrLogin_Warm_ThenDispose()
    {
        using Pkcs11Login held = _slot.Login(TokenUser.User, Pin);

        Assert.Equal("C_GetSessionInfo×1, C_GetTokenInfo×1", NativeCalls.Of(_token, () => _slot.ShareOrLogin(Pin).Dispose()));
    }

    // No probe: only the token re-read.
    [Fact]
    public void TryShareLogin_Warm_ThenDispose()
    {
        using Pkcs11Login held = _slot.Login(TokenUser.User, Pin);

        Assert.Equal("C_GetTokenInfo×1", NativeCalls.Of(_token, () =>
        {
            Assert.True(_slot.TryShareLogin(out Pkcs11Login? share));
            share!.Dispose();
        }));
    }

    // The server pattern (hold one Pkcs11Login, open a session per unit of work): the session opened and closed, plus
    // the access check of a read/write one. Nothing about the login is sent.
    [Theory]
    [InlineData(SessionAccess.ReadWrite, "C_CloseSession×1, C_GetSessionInfo×1, C_OpenSession×1")]
    [InlineData(SessionAccess.ReadOnly, "C_CloseSession×1, C_OpenSession×1")]
    public void LoginOpenSession_ThenDispose(SessionAccess access, string calls)
    {
        using Pkcs11Login login = _slot.Login(TokenUser.User, Pin);

        Assert.Equal(calls, NativeCalls.Of(_token, () => login.OpenSession(access).Dispose()));
    }

    // A slot session holds no login: opened and closed, plus the access check of a read/write one.
    [Theory]
    [InlineData(SessionAccess.ReadOnly, "C_CloseSession×1, C_OpenSession×1")]
    [InlineData(SessionAccess.ReadWrite, "C_CloseSession×1, C_GetSessionInfo×1, C_OpenSession×1")]
    public void SlotOpenSession_ThenDispose(SessionAccess access, string calls)
        => Assert.Equal(calls, NativeCalls.Of(_token, () => _slot.OpenSession(access).Dispose()));
}
