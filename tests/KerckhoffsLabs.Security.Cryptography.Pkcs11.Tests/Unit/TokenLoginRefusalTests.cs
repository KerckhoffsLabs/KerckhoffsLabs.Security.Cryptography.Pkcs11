using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The token login's edges: a PIN the token refused is never sent again for the same login (each wrong PIN costs one
/// of the PIN's retries); a login the module made is never left on the token unrecorded; and the module's answers are
/// read as evidence only where PKCS#11 defines them.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class TokenLoginRefusalTests : IDisposable
{
    private readonly ThrowingLogger _logger = new();
    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public TokenLoginRefusalTests()
    {
        _library = _module.Load(new Pkcs11LibraryOptions { LoggerFactory = new CapturingLoggerFactory(_logger) });
        _pin = new SecurePin(_module.ExpectedPin);
    }

    public void Dispose()
    {
        _logger.Armed = false;
        _pin.Dispose();
        _library.Dispose();
        _module.Dispose();
    }

    private Pkcs11Slot Slot => Assert.Single(_library.GetSlotList());

    private static SecurePin Wrong() => new("9999");

    // The per-request pattern with a stale PIN in the secret store: no login is ever held, so each request logs in
    // afresh. The PIN goes to the token once; the other requests are refused before the module.
    [Fact]
    public void ShareOrLogin_StalePin_PerRequest_SentOnce()
    {
        _module.LoginLockAfter = 3;

        for (int request = 0; request < 5; request++)
        {
            var ex = Assert.Throws<Pkcs11AuthenticationException>(() => Slot.ShareOrLogin(LoginCredential.FromPinSource(Wrong)));
            Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        }

        Assert.Equal(1, _module.LoginCalls);
        Assert.Equal(1, _module.WrongPins(CKU.CKU_USER)); // one retry spent, of three
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Assert.True(login.IsActive); // not locked
    }

    // The refusal is the PIN's: a different PIN is sent; the right one logs in, and the wrong one stays refused, since
    // the token's accepting another PIN says nothing of it.
    [Fact]
    public void Login_RefusedPin_NotResent_ADifferentOneIs_TheRefusalOutlivesASuccess()
    {
        _module.LoginLockAfter = 5;
        using (SecurePin wrong = Wrong())
        {
            Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, wrong));
            var again = Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, wrong));
            Assert.Contains("refused this PIN before", again.Message, StringComparison.Ordinal);
        }
        Assert.Equal(1, _module.LoginCalls);

        Slot.Login(TokenUser.User, _pin).Dispose();
        Assert.Equal(2, _module.LoginCalls);

        using SecurePin stale = Wrong();
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, stale));
        Assert.Equal(2, _module.LoginCalls); // still refused: not sent
    }

    // Scoped per user: a PIN refused for the SO is still sent for the user.
    [Fact]
    public void RefusedForTheSo_StillSentForTheUser()
    {
        _module.LoginLockAfter = 5;
        using SecurePin wrong = Wrong();
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.SecurityOfficer, wrong));

        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, wrong));

        Assert.Equal(2, _module.LoginCalls);
    }

    // A PIN changed back outside the library: ForgetRefusedPins lets it be sent again.
    [Fact]
    public void ForgetRefusedPins_RefusedPinSentAgain()
    {
        _module.LoginLockAfter = 5;
        using SecurePin wrong = Wrong();
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, wrong));
        _module.ExpectedPin = "9999"u8.ToArray();

        Slot.ForgetRefusedPins();
        using Pkcs11Login login = Slot.Login(TokenUser.User, wrong);

        Assert.True(login.IsActive);
        Assert.Equal(2, _module.LoginCalls);
    }

    // A PIN set through the library forgets the refusal of that PIN, which is the token's now; the other refusals stand.
    [Fact]
    public void SetPin_ForgetsTheNewPinsRefusal_OthersStand()
    {
        _module.LoginLockAfter = 5;
        using var first = new SecurePin("1111");
        using var second = new SecurePin("2222");
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, first));
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, second));
        Assert.Equal(2, Slot.LoginRecord.RefusedPins.Count);

        using (Pkcs11Login login = Slot.Login(TokenUser.User, _pin))
        using (Pkcs11Session session = login.OpenSession())
            session.SetPinWithPin(_pin, second);

        Assert.Equal(1, Slot.LoginRecord.RefusedPins.Count);
        int loginCalls = _module.LoginCalls;
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, first));
        Assert.Equal(loginCalls, _module.LoginCalls);
        using Pkcs11Login after = Slot.Login(TokenUser.User, second);
        Assert.True(after.IsActive);
        Assert.Equal(0, _module.WrongPins(CKU.CKU_USER)); // reset by the right PIN
    }

    // A logger that throws after C_Login answered CKR_OK, on the way to recording the login: the login is logged back
    // out, or (the logger throwing on that way too) recorded as left on the token, so the next login logs it out and
    // logs in, rather than taking it for a foreign one while another session keeps the token logged in.
    [Fact]
    public void LoggerThrowsAfterLoginSucceeded_NotLeftUnrecorded_NextLoginWorks()
    {
        using Pkcs11Session other = Slot.OpenSession(SessionAccess.ReadOnly);
        _module.DuringLogin = _ => _logger.Armed = true;

        Assert.Throws<InvalidOperationException>(() => Slot.Login(TokenUser.User, _pin));
        _logger.Armed = false;
        _module.DuringLogin = null;

        Assert.True(Slot.LoginRecord.MayStillBeLoggedIn || _module.LoggedIn is null);
        using Pkcs11Login next = Slot.Login(TokenUser.User, _pin);
        Assert.True(next.IsActive);
    }

    // The module answers CKR_OK to the login but reports a public state: the login is refused, and logged back out in
    // case the module did make it, so it is not left on the token for the next login to take for a foreign one.
    [Fact]
    public void LoginAccepted_StateSaysPublic_Refused_AndLoggedBackOut()
    {
        using Pkcs11Session other = Slot.OpenSession(SessionAccess.ReadOnly);
        _module.ReportedState = CKS.CKS_RO_PUBLIC_SESSION;

        var ex = Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, _pin));

        Assert.Equal(CKR.CKR_USER_NOT_LOGGED_IN, ex.ReturnValue);
        Assert.Equal(1, _module.LogoutCalls);
        Assert.Null(_module.LoggedIn);
    }

    // A session state PKCS#11 does not define is no evidence: the login is not refused for it, nor ended by a probe.
    [Fact]
    public void UndefinedSessionState_IsNoEvidence()
    {
        _module.ReportedState = (CKS)0x8000_0001;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);

        var again = Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, _pin));

        Assert.Equal(CKR.CKR_USER_ALREADY_LOGGED_IN, again.ReturnValue); // the probe did not end it
        Assert.True(login.IsActive);
    }

    // An SO login left on the token (its C_Logout failed) on a module that reports the SO as a user on sessions opened
    // after the login (Kryoptic): the next SO login trusts the module's CKR_USER_ALREADY_LOGGED_IN over that state,
    // logs the left-behind login out and logs in afresh.
    [Fact]
    public void SoLeftBehind_ModuleReportsSoAsUser_NextSoLoginRecovers()
    {
        _module.ReportsSoAsUserOnLaterSessions = true;
        using Pkcs11Session keeper = Slot.OpenSession(SessionAccess.ReadWrite);
        Pkcs11Login so = Slot.Login(TokenUser.SecurityOfficer, _pin);
        _module.FailNext("C_Logout", CKR.CKR_DEVICE_ERROR);
        so.Dispose();
        Assert.Equal(CKU.CKU_SO, _module.LoggedIn); // left on the token

        using Pkcs11Login again = Slot.Login(TokenUser.SecurityOfficer, _pin);

        Assert.True(again.IsActive);
        Assert.Equal(CKU.CKU_SO, _module.LoggedIn);
    }

    private sealed class ThrowingLogger : ILogger
    {
        public volatile bool Armed;

        IDisposable? ILogger.BeginScope<TState>(TState state) => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (Armed)
                throw new InvalidOperationException("logger down");
        }
    }
}
