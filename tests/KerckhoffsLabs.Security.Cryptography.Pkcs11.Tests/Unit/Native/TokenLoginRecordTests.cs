using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// The module-wide login record over a token that follows the spec's login rules
/// (<see cref="LoginTokenModule"/>): one anchor session per login, a share of an existing login still
/// sends the PIN, another user is refused before the module, the last holder logs out, and a login the
/// module reported gone starts a new generation.
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

    [Fact]
    public void SecondLogin_SameUser_SendsPin_AndShares()
    {
        using LoginHold first = Record.Login(_library, TokenUser.User, _pin, username: null);
        long generation = Record.Generation;

        using LoginHold second = Record.Login(_library, TokenUser.User, _pin, username: null);

        Assert.Equal(2, _module.LoginCalls);
        Assert.Single(_module.OpenSessions);
        Assert.True(first.IsActive);
        Assert.True(second.IsActive);
        Assert.Equal(generation, Record.Generation);
        Assert.Equal(generation, second.Generation);
    }

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
    public void LoginUser_SameUsername_Shares()
    {
        using LoginHold first = Record.Login(_library, TokenUser.User, _pin, "alice");
        using LoginHold second = Record.Login(_library, TokenUser.User, _pin, "alice");

        Assert.Equal(2, _module.LoginCalls);
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

    // Decision 5: CKR_USER_NOT_LOGGED_IN is not evidence that the login is gone.
    [Fact]
    public void SharedLogin_UserNotLoggedIn_Propagates_AndKeepsTheLogin()
    {
        using LoginHold first = Record.Login(_library, TokenUser.User, _pin, username: null);
        _module.FailSession(Assert.Single(_module.OpenSessions).Handle, CKR.CKR_USER_NOT_LOGGED_IN);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => Record.Login(_library, TokenUser.User, _pin, username: null));

        Assert.Equal(CKR.CKR_USER_NOT_LOGGED_IN, ex.ReturnValue);
        Assert.True(first.IsActive);
        Assert.True(Record.IsLoggedIn);
    }

    // A library's disposal releases its holds; a share that lands after that release, while the library is
    // being disposed, is refused rather than left held by a disposed library, which would keep the login.
    [Fact]
    public void Share_ThroughALibraryBeingDisposed_IsRefused_AndTakesNoHold()
    {
        using LoginHold held = Record.Login(_library, TokenUser.User, _pin, username: null);
        Pkcs11Library other = _module.Load();
        _module.DuringLogin = _ =>
        {
            _module.DuringLogin = null;
            var disposer = new Thread(other.Dispose);
            disposer.Start();
            disposer.Join();
        };

        Assert.Throws<ObjectDisposedException>(() => Record.Login(other, TokenUser.User, _pin, username: null));

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
        using LoginHold second = Record.Login(_library, TokenUser.User, _pin, username: null);
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
        using LoginHold theirs = Record.Login(other, TokenUser.User, _pin, username: null);

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

    [Fact]
    public void ConcurrentFirstLogin_OpensOneAnchor()
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

        Assert.All(failures, Assert.Null);
        var anchor = Assert.Single(_module.OpenSessions);
        Assert.True(anchor.ReadWrite);
        Assert.Equal(2, _module.LoginCalls);
        Assert.All(holds, h => Assert.True(h!.IsActive));

        foreach (LoginHold? hold in holds)
            hold!.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
        Assert.Empty(_module.OpenSessions);
    }

    // The gate is thread-affine, so the operation is held on the test thread and the release runs on another.
    [Fact]
    public void EnterOperation_HoldsOffTheFinalLogout()
    {
        LoginHold hold = Record.Login(_library, TokenUser.User, _pin, username: null);
        var release = new Thread(hold.Dispose);
        using (Record.EnterOperation())
        {
            release.Start();
            Assert.False(release.Join(TimeSpan.FromMilliseconds(200)));
            Assert.Equal(0, _module.LogoutCalls);
        }

        Assert.True(release.Join(TimeSpan.FromSeconds(30)));
        Assert.Equal(1, _module.LogoutCalls);
    }

    // Review I1: a share whose login the module reports ended while its C_Login is in flight takes no hold,
    // so the next login is not kept from logging out by a stale one.
    [Fact]
    public void ShareLogin_EndedWhileSending_TakesNoHold_AndTheNextLoginStillLogsOut()
    {
        using LoginHold first = Record.Login(_library, TokenUser.User, _pin, username: null);
        _module.DuringLogin = _ =>
        {
            _module.DuringLogin = null;
            Record.MarkEnded(CKR.CKR_DEVICE_REMOVED);
        };

        Assert.Throws<ObjectDisposedException>(() => Record.Login(_library, TokenUser.User, _pin, username: null));
        Assert.False(Record.IsLoggedIn);
        Assert.Empty(_module.OpenSessions);

        using LoginHold next = Record.Login(_library, TokenUser.User, _pin, username: null);
        next.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
        Assert.Empty(_module.OpenSessions);
    }

    // Review I2: a share holds the gate shared, so an operation on the slot runs while its C_Login is in flight.
    [Fact]
    public void ShareLogin_InFlight_DoesNotBlockOperations()
    {
        using LoginHold first = Record.Login(_library, TokenUser.User, _pin, username: null);
        using var entered = new ManualResetEventSlim();
        using var proceed = new ManualResetEventSlim();
        _module.DuringLogin = _ =>
        {
            entered.Set();
            proceed.Wait(TimeSpan.FromSeconds(30));
        };
        LoginHold? shared = null;
        var login = new Thread(() => shared = Record.Login(_library, TokenUser.User, _pin, username: null));
        login.Start();
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken));
            var operation = new Thread(() => Record.EnterOperation().Dispose());
            operation.Start();
            Assert.True(operation.Join(TimeSpan.FromSeconds(5)), "an operation waited for a share login");
        }
        finally
        {
            proceed.Set();
            Assert.True(login.Join(TimeSpan.FromSeconds(30)));
        }

        using LoginHold held = Assert.IsType<LoginHold>(shared);
        Assert.True(held.IsActive);
    }

    // Review I3: releasing a share inside an operation is refused before anything changes, so releasing it
    // afterwards still logs out.
    [Fact]
    public void ReleaseInsideOperation_IsRefused_AndLeavesTheHold()
    {
        using LoginHold hold = Record.Login(_library, TokenUser.User, _pin, username: null);

        using (Record.EnterOperation())
        {
            Assert.Throws<InvalidOperationException>(hold.Dispose);
            Assert.Throws<InvalidOperationException>(() => Record.ReleaseHoldersOf(_library));
            Assert.True(hold.IsActive);
        }

        Assert.Equal(0, _module.LogoutCalls);
        hold.Dispose();
        Assert.False(hold.IsActive);
        Assert.Equal(1, _module.LogoutCalls);
        Assert.Empty(_module.OpenSessions);
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
