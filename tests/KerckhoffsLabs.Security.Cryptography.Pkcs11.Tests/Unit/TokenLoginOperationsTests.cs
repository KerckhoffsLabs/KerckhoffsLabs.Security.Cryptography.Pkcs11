using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// How a token's login transitions meet the operations in flight on its sessions: a first login waits for those
/// already running (PKCS#11 C_Login: they should finish first), and only for those; the logout of a login left on the
/// token waits for operations that started after it was decided; and the work handed to the thread that holds the
/// transition runs in full, whatever one piece of it throws.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class TokenLoginOperationsTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    private readonly CapturingLogger _logger = new();
    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public TokenLoginOperationsTests()
    {
        _library = _module.Load(new Pkcs11LibraryOptions { LoggerFactory = new CapturingLoggerFactory(_logger) });
        _pin = new SecurePin(_module.ExpectedPin);
    }

    public void Dispose()
    {
        _pin.Dispose();
        _library.Dispose();
        _module.Dispose();
    }

    private Pkcs11Slot Slot => Assert.Single(_library.GetSlotList());

    // A search on another session runs when the login is asked for: C_Login is sent once it has ended, not into it.
    [Fact]
    public void FirstLogin_WaitsForAnOperationInFlightOnAnotherSession()
    {
        using Pkcs11Session other = Slot.OpenSession(SessionAccess.ReadOnly);
        TokenLoginRecord record = Slot.LoginRecord;
        using var inSearch = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        _module.DuringFind = () =>
        {
            _module.DuringFind = null;
            inSearch.Set();
            release.Wait(Timeout, TestContext.Current.CancellationToken);
        };
        BackgroundWork search = BackgroundWork.Run(() => other.FindCertificates().Dispose());
        Assert.True(inSearch.Wait(Timeout, TestContext.Current.CancellationToken));

        using var waiting = new ManualResetEventSlim();
        record.WhileWaitingForOperations = waiting.Set;
        int inFlightAtLogin = -1;
        _module.DuringLogin = _ => inFlightAtLogin = record.OperationsInFlight;
        Pkcs11Login? login = null;
        BackgroundWork logIn = BackgroundWork.Run(() => login = Slot.Login(TokenUser.User, _pin));

        // The hook runs at the wait itself: no guess at when the thread got there.
        Assert.True(waiting.Wait(Timeout, TestContext.Current.CancellationToken));
        Assert.True(logIn.IsAlive);
        Assert.Equal(0, _module.LoginCalls);

        release.Set();
        Assert.True(search.Join(Timeout));
        Assert.True(logIn.Join(Timeout));
        using (login)
        {
            Assert.True(login!.IsActive);
            Assert.Equal(1, _module.LoginCalls);
            Assert.Equal(0, inFlightAtLogin);
        }
    }

    // The wait is for the operations running when the login began: one that starts during the wait does not hold the
    // login back, so a busy token cannot starve it.
    [Fact]
    public void FirstLogin_DoesNotWaitForOperationsThatStartDuringItsWait()
    {
        using Pkcs11Session first = Slot.OpenSession(SessionAccess.ReadOnly);
        using Pkcs11Session second = Slot.OpenSession(SessionAccess.ReadOnly);
        TokenLoginRecord record = Slot.LoginRecord;
        using var inFirst = new ManualResetEventSlim();
        using var releaseFirst = new ManualResetEventSlim();
        using var inSecond = new ManualResetEventSlim();
        using var releaseSecond = new ManualResetEventSlim();
        int searches = 0;
        _module.DuringFind = () =>
        {
            if (Interlocked.Increment(ref searches) == 1)
            {
                inFirst.Set();
                releaseFirst.Wait(Timeout, TestContext.Current.CancellationToken);
            }
            else
            {
                inSecond.Set();
                releaseSecond.Wait(Timeout, TestContext.Current.CancellationToken);
            }
        };
        BackgroundWork firstSearch = BackgroundWork.Run(() => first.FindCertificates().Dispose());
        Assert.True(inFirst.Wait(Timeout, TestContext.Current.CancellationToken));

        BackgroundWork? secondSearch = null;
        record.WhileWaitingForOperations = () =>
        {
            secondSearch = BackgroundWork.Run(() => second.FindCertificates().Dispose());
            Assert.True(inSecond.Wait(Timeout, TestContext.Current.CancellationToken));
        };
        Pkcs11Login? login = null;
        BackgroundWork logIn = BackgroundWork.Run(() => login = Slot.Login(TokenUser.User, _pin));
        Assert.True(inSecond.Wait(Timeout, TestContext.Current.CancellationToken));

        releaseFirst.Set();
        Assert.True(logIn.Join(Timeout));
        try
        {
            Assert.True(login!.IsActive);
            Assert.True(secondSearch!.IsAlive); // still in its search: the login did not wait for it
        }
        finally
        {
            releaseSecond.Set();
            Assert.True(firstSearch.Join(Timeout));
            Assert.True(secondSearch!.Join(Timeout));
            login?.Dispose();
        }
    }

    // A login made from inside an operation on the token cannot wait for that operation: it goes ahead.
    [Fact]
    public void FirstLogin_FromInsideAnOperation_DoesNotWaitForIt()
    {
        using Pkcs11Session session = Slot.OpenSession(SessionAccess.ReadOnly);
        bool active = false;
        _module.DuringFind = () =>
        {
            _module.DuringFind = null;
            using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
            active = login.IsActive;
        };

        BackgroundWork search = BackgroundWork.Run(() => session.FindCertificates().Dispose());

        Assert.True(search.Join(Timeout));
        Assert.True(active);
        Assert.Equal(1, _module.LoginCalls);
    }

    // The C_Logout of the last hold fails, so the login is left on the token, and its logout is decided with no
    // operation in flight; a search starts on another session before that logout runs. The logout re-checks, leaves
    // the login for the search's end, and the search's end sends it: never a C_Logout inside the search.
    [Fact]
    public void LeftBehindLogout_OperationStartedSinceItWasDecided_WaitsForIt()
    {
        using Pkcs11Session keeper = Slot.OpenSession(SessionAccess.ReadOnly);
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using var inSearch = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        int logoutsInSearch = -1;
        _module.DuringFind = () =>
        {
            _module.DuringFind = null;
            inSearch.Set();
            release.Wait(Timeout, TestContext.Current.CancellationToken);
            logoutsInSearch = _module.LogoutCalls;
        };
        BackgroundWork? search = null;
        _module.FailNext("C_Logout", CKR.CKR_DEVICE_ERROR);
        _module.DuringLogout = _ =>
        {
            // On the thread that holds the transition, sending the C_Logout that fails: the search starts now, after
            // the decision to log out with nothing in flight, before the left-behind logout runs.
            _module.DuringLogout = null;
            search = BackgroundWork.Run(() => keeper.FindCertificates().Dispose());
            Assert.True(inSearch.Wait(Timeout, TestContext.Current.CancellationToken));
        };

        login.Dispose();

        Assert.Equal(1, _module.LogoutCalls);           // the failed one only
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);   // left on the token while the search runs
        Assert.True(Slot.LoginRecord.MayStillBeLoggedIn);

        release.Set();
        Assert.True(search!.Join(Timeout));
        Assert.Equal(1, logoutsInSearch);
        Assert.Equal(2, _module.LogoutCalls);
        Assert.Null(_module.LoggedIn);
        Assert.False(Slot.LoginRecord.MayStillBeLoggedIn);
    }

    // The logout of a login left on the token answers CKR_USER_NOT_LOGGED_IN (gone meanwhile): the login is no longer
    // recorded as left behind, and the release that ran it does not throw.
    [Fact]
    public void LeftBehindLogout_AnsweredNotLoggedIn_ClearsIt()
    {
        using Pkcs11Session keeper = Slot.OpenSession(SessionAccess.ReadOnly);
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        _module.FailNext("C_Logout", CKR.CKR_DEVICE_ERROR);
        _module.FailNext("C_Logout", CKR.CKR_USER_NOT_LOGGED_IN);

        login.Dispose();

        Assert.Equal(2, _module.LogoutCalls);
        Assert.False(Slot.LoginRecord.MayStillBeLoggedIn);
    }

    // Two pieces of work handed to the thread that holds the transition: the first throws, the second still runs, the
    // throw is logged, and the login that thread was making is returned rather than replaced by the throw.
    [Fact]
    public void HandOffs_OneThrows_TheOthersRun_AndTheLoginStands()
    {
        TokenLoginRecord record = Slot.LoginRecord;
        bool secondRan = false;
        record.WhileHoldingTransition = () =>
        {
            record.WhileHoldingTransition = null;
            record.UnderTransition(() => throw new InvalidOperationException("hand-off failed"));
            record.UnderTransition(() => secondRan = true);
        };

        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);

        Assert.True(login.IsActive);
        Assert.True(secondRan);
        Assert.Contains(_logger.Entries, entry => entry.Level == LogLevel.Warning
            && entry.EventId.Name == nameof(Log.TokenHandOffFailed));
    }
}
