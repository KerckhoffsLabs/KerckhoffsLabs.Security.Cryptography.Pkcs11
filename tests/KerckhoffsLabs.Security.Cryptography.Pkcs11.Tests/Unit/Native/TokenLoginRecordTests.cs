using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// The module-wide login record over a token that follows the spec's login rules
/// (<see cref="LoginTokenModule"/>): one anchor session per login, a second login is refused before the module
/// with no PIN sent (a share is taken explicitly), the last holder logs out once no operation is in flight, a
/// login the module reported gone starts a new generation, and a login the record left on the token is logged
/// out and logged in again while one made outside the library is refused.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class TokenLoginRecordTests : IDisposable
{
    private static readonly NativeCULong Slot = (NativeCULong)LoginTokenModule.SlotId;

    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public TokenLoginRecordTests()
    {
        _library = _module.Load();
        _pin = new SecurePin(_module.ExpectedPin);
    }

    private TokenLoginRecord Record => TokenLoginRegistry.Of(_library.LowLevelLibrary!.Module).For(Slot);

    public void Dispose()
    {
        _pin.Dispose();
        _library.Dispose();
        _module.Dispose();
    }

    [Theory]
    [InlineData(TokenUser.User)]
    [InlineData(TokenUser.SecurityOfficer)]
    public void FirstLogin_OpensAnchor_ReadWrite_ForUserAndSo(TokenUser user)
    {
        using LoginHold hold = Record.Login(_library, user, _pin, username: null);

        var anchor = Assert.Single(_module.OpenSessions);
        Assert.True(anchor.ReadWrite);
        Assert.Equal([CKR.CKR_OK], _module.OpenSessionResults);
        Assert.Equal(user == TokenUser.User ? CKU.CKU_USER : CKU.CKU_SO, _module.LoggedIn);
        Assert.True(hold.IsActive);
        Assert.True(Record.IsLoggedIn);
        Assert.Equal(user, Record.User);
        Assert.NotNull(Record.Anchor);
    }

    [Fact]
    public void UserAnchor_FallsBackToReadOnly_OnWriteProtectedToken()
    {
        _module.WriteProtected = true;

        using LoginHold hold = Record.Login(_library, TokenUser.User, _pin, username: null);

        Assert.Equal([CKR.CKR_TOKEN_WRITE_PROTECTED, CKR.CKR_OK], _module.OpenSessionResults);
        Assert.False(Assert.Single(_module.OpenSessions).ReadWrite);
        Assert.Equal(1, _module.LoginCalls);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
        Assert.True(hold.IsActive);
    }

    [Fact]
    public void UserAnchor_FallsBackToReadOnly_WhenNoReadWriteSessionLeft()
    {
        _module.MaxRwSessions = 1;
        using Pkcs11Session slotSession = Assert.Single(_library.GetSlotList()).OpenSession(SessionAccess.ReadWrite);

        using LoginHold hold = Record.Login(_library, TokenUser.User, _pin, username: null);

        Assert.Equal([CKR.CKR_OK, CKR.CKR_SESSION_COUNT, CKR.CKR_OK], _module.OpenSessionResults);
        Assert.False(_module.OpenSessions[^1].ReadWrite);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
        Assert.True(hold.IsActive);
        Assert.True(Record.IsLoggedIn);
    }

    [Fact]
    public void SoAnchor_DoesNotFallBack()
    {
        _module.MaxRwSessions = 1;
        using Pkcs11Session slotSession = Assert.Single(_library.GetSlotList()).OpenSession(SessionAccess.ReadWrite);

        var ex = Assert.Throws<Pkcs11SessionException>(
            () => Record.Login(_library, TokenUser.SecurityOfficer, _pin, username: null));

        Assert.Equal(CKR.CKR_SESSION_COUNT, ex.ReturnValue);
        Assert.Equal([CKR.CKR_OK, CKR.CKR_SESSION_COUNT], _module.OpenSessionResults);
        Assert.Equal(0, _module.LoginCalls);
        Assert.Single(_module.OpenSessions);
        Assert.False(Record.IsLoggedIn);
    }

    // PKCS#11 cannot check a PIN against a login already made, so a second login is refused before the module, with
    // no PIN sent, whatever the PIN: a wrong one included.
    [Theory]
    [InlineData("1234")]
    [InlineData("9999")]
    public void SecondLogin_SameUser_IsRefusedBeforeModule_NoPinSent(string pin)
    {
        using LoginHold first = Record.Login(_library, TokenUser.User, _pin, username: null);
        long generation = Record.Generation;
        using var second = new SecurePin(pin);

        var ex = Assert.Throws<Pkcs11AuthenticationException>(
            () => Record.Login(_library, TokenUser.User, second, username: null));

        Assert.Equal(CKR.CKR_USER_ALREADY_LOGGED_IN, ex.ReturnValue);
        Assert.Contains("TryShareLogin", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, _module.LoginCalls);
        Assert.Single(_module.OpenSessions);
        Assert.True(first.IsActive);
        Assert.Equal(generation, Record.Generation);
    }

    [Fact]
    public void TryShare_SameUser_AddsAHolder_WithoutCallingTheModule()
    {
        using LoginHold first = Record.Login(_library, TokenUser.User, _pin, username: null);
        int calls = _module.LoginCalls;

        using LoginHold second = Assert.IsType<LoginHold>(Record.TryShare(_library, TokenUser.User, username: null));

        Assert.Equal(calls, _module.LoginCalls);
        Assert.True(second.IsActive);
        Assert.Equal(first.Generation, second.Generation);
        Assert.Null(Record.TryShare(_library, TokenUser.SecurityOfficer, username: null));
        Assert.Null(Record.TryShare(_library, TokenUser.User, "alice"));

        first.Dispose();
        Assert.Equal(0, _module.LogoutCalls);
        second.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
    }

    [Fact]
    public void TryShare_WithNoLogin_ReturnsNull()
        => Assert.Null(Record.TryShare(_library, TokenUser.User, username: null));

    [Fact]
    public void SecondLogin_OtherUser_IsRefusedBeforeModule()
    {
        using LoginHold user = Record.Login(_library, TokenUser.User, _pin, username: null);

        var ex = Assert.Throws<Pkcs11AuthenticationException>(
            () => Record.Login(_library, TokenUser.SecurityOfficer, _pin, username: null));

        Assert.Equal(CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN, ex.ReturnValue);
        Assert.Equal(1, _module.LoginCalls);
        Assert.True(user.IsActive);
    }

    [Fact]
    public void LoginUser_DifferentUsername_IsRefusedBeforeModule()
    {
        using LoginHold alice = Record.Login(_library, TokenUser.User, _pin, "alice");

        var ex = Assert.Throws<Pkcs11AuthenticationException>(
            () => Record.Login(_library, TokenUser.User, _pin, "bob"));

        Assert.Equal(CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN, ex.ReturnValue);
        Assert.DoesNotContain("alice", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("bob", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, _module.LoginCalls);
        Assert.Equal("alice", Record.Username);
    }

    [Fact]
    public void LoginUser_SameUsername_IsRefused_AndSharedExplicitly()
    {
        using LoginHold first = Record.Login(_library, TokenUser.User, _pin, "alice");

        var ex = Assert.Throws<Pkcs11AuthenticationException>(() => Record.Login(_library, TokenUser.User, _pin, "alice"));
        Assert.Equal(CKR.CKR_USER_ALREADY_LOGGED_IN, ex.ReturnValue);
        Assert.DoesNotContain("alice", ex.Message, StringComparison.Ordinal);

        using LoginHold second = Assert.IsType<LoginHold>(Record.TryShare(_library, TokenUser.User, "alice"));
        Assert.Equal(1, _module.LoginCalls);
        Assert.True(second.IsActive);
    }

    [Fact]
    public void Login_Then_LoginUser_SameType_IsRefused()
    {
        using LoginHold plain = Record.Login(_library, TokenUser.User, _pin, username: null);

        var ex = Assert.Throws<Pkcs11AuthenticationException>(
            () => Record.Login(_library, TokenUser.User, _pin, "alice"));

        Assert.Equal(CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN, ex.ReturnValue);
        Assert.Equal(1, _module.LoginCalls);
    }

    [Fact]
    public void WrongPin_OnFirstLogin_ClosesAnchor_AndThrows()
    {
        using var wrong = new SecurePin("0000"u8);

        var ex = Assert.Throws<Pkcs11AuthenticationException>(
            () => Record.Login(_library, TokenUser.User, wrong, username: null));

        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        Assert.Empty(_module.OpenSessions);
        Assert.False(Record.IsLoggedIn);
        Assert.Null(Record.Anchor);
        Assert.Null(Record.User);
    }

    [Fact]
    public void SharedLogin_AnchorLost_EndsTheLogin_AndLogsInAfresh()
    {
        using LoginHold first = Record.Login(_library, TokenUser.User, _pin, username: null);

        // Closed underneath the record, so the share's C_Login answers CKR_SESSION_HANDLE_INVALID.
        var anchor = Assert.Single(_module.OpenSessions);
        Assert.Equal(CKR.CKR_OK, _library.LowLevelLibrary!.C_CloseSession((NativeCULong)anchor.Handle));

        // The anchor reported lost is unambiguous evidence the login is gone (decision 5): it ends, the first
        // holder goes inactive with it, and the same Login then logs in from scratch on a new anchor.
        using LoginHold second = Record.Login(_library, TokenUser.User, _pin, username: null);

        Assert.False(first.IsActive);
        Assert.True(second.IsActive);
        Assert.True(Record.IsLoggedIn);
        Assert.NotEqual(first.Generation, second.Generation);
        var newAnchor = Assert.Single(_module.OpenSessions);
        Assert.NotEqual(anchor.Handle, newAnchor.Handle);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
    }

    // Decision 5: CKR_USER_NOT_LOGGED_IN is not evidence that the login is gone. The second login's probe of the anchor
    // gets it, keeps the login, and refuses as for any second login.
    [Fact]
    public void SecondLogin_ProbeAnswersUserNotLoggedIn_KeepsTheLogin_AndRefuses()
    {
        using LoginHold first = Record.Login(_library, TokenUser.User, _pin, username: null);
        _module.FailSession(Assert.Single(_module.OpenSessions).Handle, CKR.CKR_USER_NOT_LOGGED_IN);

        var ex = Assert.Throws<Pkcs11AuthenticationException>(() => Record.Login(_library, TokenUser.User, _pin, username: null));

        Assert.Equal(CKR.CKR_USER_ALREADY_LOGGED_IN, ex.ReturnValue);
        Assert.Equal(1, _module.LoginCalls);
        Assert.True(first.IsActive);
        Assert.True(Record.IsLoggedIn);
    }

    // A library's disposal releases its holds; a share through a library being disposed is refused rather than left
    // held by a disposed library, which would keep the login.
    [Fact]
    public void Share_ThroughALibraryBeingDisposed_IsRefused_AndTakesNoHold()
    {
        using LoginHold held = Record.Login(_library, TokenUser.User, _pin, username: null);
        Pkcs11Library other = _module.Load();
        other.Dispose();

        Assert.Throws<ObjectDisposedException>(() => Record.TryShare(other, TokenUser.User, username: null));
        Assert.Throws<ObjectDisposedException>(() => Record.Share(held, other));

        held.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
        Assert.False(Record.IsLoggedIn);
    }

    [Fact]
    public void FirstLogin_ThroughALibraryBeingDisposed_IsRefused_AndLogsBackOut()
    {
        Pkcs11Library other = _module.Load();
        _module.DuringLogin = _ =>
        {
            _module.DuringLogin = null;
            var disposer = new Thread(other.Dispose);
            disposer.Start();
            disposer.Join();
        };

        Assert.Throws<ObjectDisposedException>(() => Record.Login(other, TokenUser.User, _pin, username: null));

        Assert.False(Record.IsLoggedIn);
        Assert.Null(_module.LoggedIn);
        Assert.Empty(_module.OpenSessions);
    }

    [Fact]
    public void LastHolderReleased_LogsOut_ThenClosesAnchor()
    {
        using LoginHold first = Record.Login(_library, TokenUser.User, _pin, username: null);
        using LoginHold second = Record.Share(first, _library);
        long generation = Record.Generation;

        first.Dispose();
        Assert.Equal(0, _module.LogoutCalls);
        Assert.Single(_module.OpenSessions);
        Assert.False(first.IsActive);
        Assert.True(second.IsActive);

        second.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
        Assert.Empty(_module.OpenSessions);
        Assert.False(Record.IsLoggedIn);
        Assert.Null(Record.Anchor);
        Assert.Equal(generation, Record.Generation);

        second.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
    }

    [Fact]
    public void MarkEnded_StartsNewGeneration_OldHoldsInactive_NoLogoutForThem()
    {
        using LoginHold old = Record.Login(_library, TokenUser.User, _pin, username: null);
        long generation = Record.Generation;

        Record.MarkEnded(CKR.CKR_DEVICE_REMOVED);

        Assert.NotEqual(generation, Record.Generation);
        Assert.False(old.IsActive);
        Assert.False(Record.IsLoggedIn);
        Assert.Empty(_module.OpenSessions);

        old.Dispose();
        Assert.Equal(0, _module.LogoutCalls);

        using LoginHold fresh = Record.Login(_library, TokenUser.User, _pin, username: null);
        Assert.True(fresh.IsActive);
        Assert.False(old.IsActive);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
    }

    [Fact]
    public void Share_AddsAHolder_ThatKeepsTheLogin()
    {
        using LoginHold login = Record.Login(_library, TokenUser.User, _pin, username: null);
        using LoginHold session = Record.Share(login, _library);

        login.Dispose();
        Assert.Equal(0, _module.LogoutCalls);
        Assert.True(session.IsActive);
        Assert.Equal(1, _module.LoginCalls);

        session.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
    }

    [Fact]
    public void Share_OfAnInactiveHold_Throws()
    {
        using LoginHold login = Record.Login(_library, TokenUser.User, _pin, username: null);
        login.Dispose();

        Assert.Throws<ObjectDisposedException>(() => Record.Share(login, _library));
    }

    [Fact]
    public void ReleaseHoldersOf_Library_DropsOnlyItsHolders()
    {
        using Pkcs11Library other = _module.Load();
        using LoginHold mine = Record.Login(_library, TokenUser.User, _pin, username: null);
        LoginHold mineToo = Record.Share(mine, _library);
        using LoginHold theirs = Assert.IsType<LoginHold>(Record.TryShare(other, TokenUser.User, username: null));

        Record.ReleaseHoldersOf(_library);

        Assert.False(mine.IsActive);
        Assert.False(mineToo.IsActive);
        Assert.True(theirs.IsActive);
        Assert.Equal(0, _module.LogoutCalls);

        theirs.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
        Assert.Empty(_module.OpenSessions);

        mine.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
    }

    // Two first logins at once: the transitions are serialized, so one logs in on one anchor and the other, finding
    // that login, is refused before the module.
    [Fact]
    public void ConcurrentFirstLogin_OpensOneAnchor_AndRefusesTheOther()
    {
        using var barrier = new Barrier(2);
        var holds = new LoginHold?[2];
        var failures = new Exception?[2];
        CancellationToken cancellation = TestContext.Current.CancellationToken;
        // Any exception a login throws is kept for the assertion below, whatever its type: here the test thread's
        // Record is the token's login record, hence Xunit.Record.
        Thread[] threads = [.. Enumerable.Range(0, 2).Select(i => new Thread(() => failures[i] = Xunit.Record.Exception(() =>
        {
            barrier.SignalAndWait(cancellation);
            holds[i] = Record.Login(_library, TokenUser.User, _pin, username: null);
        })))];
        foreach (Thread thread in threads)
            thread.Start();
        foreach (Thread thread in threads)
            Assert.True(thread.Join(TimeSpan.FromSeconds(30)));

        LoginHold hold = Assert.Single(holds.OfType<LoginHold>());
        var refused = Assert.IsType<Pkcs11AuthenticationException>(Assert.Single(failures.OfType<Exception>()));
        Assert.Equal(CKR.CKR_USER_ALREADY_LOGGED_IN, refused.ReturnValue);
        var anchor = Assert.Single(_module.OpenSessions);
        Assert.True(anchor.ReadWrite);
        Assert.Equal(1, _module.LoginCalls);

        hold.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
        Assert.Empty(_module.OpenSessions);
    }

    // The last holder's release, with an operation in flight, leaves the logout pending; it is sent as the operation
    // ends. Releasing inside the operation, on the same thread, never throws.
    [Fact]
    public void EnterOperation_HoldsOffTheFinalLogout()
    {
        LoginHold hold = Record.Login(_library, TokenUser.User, _pin, username: null);
        using (Record.EnterOperation())
        {
            hold.Dispose();
            Assert.Equal(0, _module.LogoutCalls);
            Assert.True(Record.IsLogoutPending);
            Assert.True(Record.IsLoggedIn);
            Assert.False(hold.IsActive);
        }

        Assert.False(Record.IsLogoutPending);
        Assert.Equal(1, _module.LogoutCalls);
        Assert.False(Record.IsLoggedIn);
        Assert.Empty(_module.OpenSessions);
    }

    // The logout is sent by the last operation to end, whichever thread it is on.
    [Fact]
    public void PendingLogout_IsSentByTheLastOperationToEnd()
    {
        LoginHold hold = Record.Login(_library, TokenUser.User, _pin, username: null);
        IDisposable first = Record.EnterOperation();
        IDisposable? second = null;
        var other = new Thread(() => second = Record.EnterOperation());
        other.Start();
        Assert.True(other.Join(TimeSpan.FromSeconds(30)));

        hold.Dispose();
        first.Dispose();
        Assert.Equal(0, _module.LogoutCalls);
        Assert.True(Record.IsLogoutPending);

        var ender = new Thread(() => second!.Dispose());
        ender.Start();
        Assert.True(ender.Join(TimeSpan.FromSeconds(30)));
        Assert.Equal(1, _module.LogoutCalls);
        Assert.False(Record.IsLoggedIn);
    }

    // A login while the previous login's logout is pending waits for it, then logs in afresh: the PIN is checked.
    [Fact]
    public void Login_WhileLogoutPending_WaitsForIt_ThenLogsInAfresh()
    {
        LoginHold hold = Record.Login(_library, TokenUser.User, _pin, username: null);
        long generation = Record.Generation;
        IDisposable operation = Record.EnterOperation();
        hold.Dispose();
        Assert.True(Record.IsLogoutPending);

        LoginHold? fresh = null;
        var login = new Thread(() => fresh = Record.Login(_library, TokenUser.User, _pin, username: null));
        login.Start();
        Assert.False(login.Join(TimeSpan.FromMilliseconds(100)));
        Assert.Equal(1, _module.LoginCalls);

        operation.Dispose();
        Assert.True(login.Join(TimeSpan.FromSeconds(30)));

        using LoginHold held = Assert.IsType<LoginHold>(fresh);
        Assert.Equal(1, _module.LogoutCalls);
        Assert.Equal(2, _module.LoginCalls);
        Assert.NotEqual(generation, held.Generation);
        Assert.True(held.IsActive);
    }

    // From inside an operation, a login cannot wait for the logout that waits for that operation: it throws, and the
    // logout still goes once the operation ends.
    [Fact]
    public void Login_FromInsideAnOperation_WhileLogoutPending_Throws()
    {
        LoginHold hold = Record.Login(_library, TokenUser.User, _pin, username: null);
        using (Record.EnterOperation())
        {
            hold.Dispose();
            var ex = Assert.Throws<InvalidOperationException>(
                () => Record.Login(_library, TokenUser.User, _pin, username: null));
            Assert.Contains("inside an operation", ex.Message, StringComparison.Ordinal);
        }

        Assert.Equal(1, _module.LogoutCalls);
        Assert.False(Record.IsLoggedIn);
    }

    // A first login from inside an operation (a context-login callback, say) neither waits for nor blocks it.
    [Fact]
    public void FirstLogin_FromInsideAnOperation_Works()
    {
        using (Record.EnterOperation())
        {
            using LoginHold hold = Record.Login(_library, TokenUser.User, _pin, username: null);
            Assert.True(hold.IsActive);
        }
        Assert.Equal(1, _module.LogoutCalls);
    }

    // A first login in flight (its C_Login parked in the module) does not hold off operations on the slot.
    [Fact]
    public void FirstLogin_InFlight_DoesNotBlockOperations()
    {
        using var entered = new ManualResetEventSlim();
        using var proceed = new ManualResetEventSlim();
        _module.DuringLogin = _ =>
        {
            entered.Set();
            proceed.Wait(TimeSpan.FromSeconds(30));
        };
        LoginHold? held = null;
        var login = new Thread(() => held = Record.Login(_library, TokenUser.User, _pin, username: null));
        login.Start();
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken));
            var operation = new Thread(() => Record.EnterOperation().Dispose());
            operation.Start();
            Assert.True(operation.Join(TimeSpan.FromSeconds(5)), "an operation waited for a login");
        }
        finally
        {
            proceed.Set();
            Assert.True(login.Join(TimeSpan.FromSeconds(30)));
        }

        using LoginHold hold = Assert.IsType<LoginHold>(held);
        Assert.True(hold.IsActive);
    }

    // Releasing inside an operation never throws, its library's release included: the logout waits for the operation.
    [Fact]
    public void ReleaseInsideOperation_DefersTheLogout_UntilTheOperationEnds()
    {
        using LoginHold hold = Record.Login(_library, TokenUser.User, _pin, username: null);

        using (Record.EnterOperation())
        {
            Record.ReleaseHoldersOf(_library);
            Assert.False(hold.IsActive);
            Assert.True(Record.IsLogoutPending);
            Assert.Equal(0, _module.LogoutCalls);
        }

        Assert.Equal(1, _module.LogoutCalls);
        Assert.Empty(_module.OpenSessions);
        hold.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
    }

    // A login left on the token: the anchor is lost while another session of the application stays open, so the
    // module keeps the login. The next Login finds the anchor gone and logs in afresh; the module answers that the
    // user is logged in already, and the record, knowing the login is its own, logs it out and logs in once more, so
    // the PIN is checked.
    [Fact]
    public void AnchorLost_WithAnotherSessionOpen_NextLogin_LogsTheLeftLoginOutAndLogsInAgain()
    {
        using Pkcs11Session other = Assert.Single(_library.GetSlotList()).OpenSession();
        using LoginHold first = Record.Login(_library, TokenUser.User, _pin, username: null);
        ulong anchor = _module.OpenSessions[^1].Handle;
        Assert.Equal(CKR.CKR_OK, _library.LowLevelLibrary!.C_CloseSession((NativeCULong)anchor));
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn); // the other session keeps the module logged in

        using LoginHold second = Record.Login(_library, TokenUser.User, _pin, username: null);

        Assert.False(first.IsActive);
        Assert.True(second.IsActive);
        Assert.False(Record.MayStillBeLoggedIn);
        Assert.Equal(1, _module.LogoutCalls);   // the left login, logged out on the new anchor
        Assert.Equal(3, _module.LoginCalls);    // the first login, the refused one, and the one with the PIN checked
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
    }

    // The same, with a wrong PIN: the left login is logged out and the login sent again, so the wrong PIN fails. No
    // login the record never authenticated is handed out.
    [Fact]
    public void LeftLogin_NextLogin_WithAWrongPin_Fails()
    {
        using Pkcs11Session other = Assert.Single(_library.GetSlotList()).OpenSession();
        using LoginHold first = Record.Login(_library, TokenUser.User, _pin, username: null);
        _library.LowLevelLibrary!.C_CloseSession((NativeCULong)_module.OpenSessions[^1].Handle);
        using var wrong = new SecurePin("0000"u8);

        var ex = Assert.Throws<Pkcs11AuthenticationException>(() => Record.Login(_library, TokenUser.User, wrong, username: null));

        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        Assert.False(Record.IsLoggedIn);
        Assert.Null(_module.LoggedIn);
    }

    // A C_Logout that fails leaves the module logged in (here another session keeps it); the next first login logs
    // that login out and logs in again.
    [Fact]
    public void FailedLogout_NextLogin_LogsTheLeftLoginOutAndLogsInAgain()
    {
        using Pkcs11Session other = Assert.Single(_library.GetSlotList()).OpenSession();
        LoginHold first = Record.Login(_library, TokenUser.User, _pin, username: null);
        _module.FailSession(_module.OpenSessions[^1].Handle, CKR.CKR_DEVICE_ERROR);

        first.Dispose();
        Assert.True(Record.MayStillBeLoggedIn);
        Assert.False(Record.IsLoggedIn);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);

        using LoginHold second = Record.Login(_library, TokenUser.User, _pin, username: null);
        Assert.True(second.IsActive);
        Assert.False(Record.MayStillBeLoggedIn);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
    }

    // A login made outside the library (straight through the module) is never taken over: the first login is refused
    // with a message saying so, and nothing is logged out.
    [Fact]
    public void LoggedInOutsideTheLibrary_FirstLogin_IsRefused_NothingLoggedOut()
    {
        using Pkcs11Session other = Assert.Single(_library.GetSlotList()).OpenSession();
        Assert.Equal(CKR.CKR_OK, _library.LowLevelLibrary!.C_Login((NativeCULong)other.Core.SessionId, CKU.CKU_USER,
            _module.ExpectedPin));

        var ex = Assert.Throws<Pkcs11AuthenticationException>(() => Record.Login(_library, TokenUser.User, _pin, username: null));

        Assert.Equal(CKR.CKR_USER_ALREADY_LOGGED_IN, ex.ReturnValue);
        Assert.Contains("not through this library", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, _module.LogoutCalls);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
        Assert.False(Record.IsLoggedIn);
        Assert.Single(_module.OpenSessions); // the anchor opened for the attempt was closed
    }

    [Fact]
    public void Registry_TalliesSessionsByAccess()
    {
        TokenLoginRegistry logins = TokenLoginRegistry.Of(_library.LowLevelLibrary!.Module);

        logins.SessionOpened(Slot, SessionAccess.ReadOnly);
        logins.SessionOpened(Slot, SessionAccess.ReadWrite);
        logins.SessionOpened(Slot, SessionAccess.ReadWrite);
        logins.SessionClosed(Slot, SessionAccess.ReadWrite);

        Assert.Equal((1, 1), logins.Sessions(Slot));
        Assert.Equal((0, 0), logins.Sessions((NativeCULong)7UL));
        Assert.Same(logins.For(Slot), logins.For(Slot));
    }
}
