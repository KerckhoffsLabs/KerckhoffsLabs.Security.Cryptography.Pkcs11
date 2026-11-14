using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The public login model over a token that follows the spec's login rules (<see cref="LoginTokenModule"/>):
/// a <see cref="Pkcs11Login"/> and the sessions it opens hold the login, a session never logs out, the last
/// holder does, and the login belongs to the module, whichever <see cref="Pkcs11Library"/> made it.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11LoginTests : IDisposable
{
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(30);

    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public Pkcs11LoginTests()
    {
        _library = _module.Load();
        _pin = new SecurePin(_module.ExpectedPin);
    }

    public void Dispose()
    {
        _pin.Dispose();
        _library.Dispose();
        _module.Dispose();
    }

    private static Pkcs11Slot SlotOf(Pkcs11Library library) => Assert.Single(library.GetSlotList());

    private Pkcs11Slot Slot => SlotOf(_library);

    private static byte[] Sign(Pkcs11Session session)
        => session.Core.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), new ObjectHandle(1), "data"u8);

    [Fact]
    public void TwoSessionsUnderOneLogin_BothUserFunctions()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session first = login.OpenSession();
        using Pkcs11Session second = login.OpenSession();

        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, first.GetSessionInfo().State);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, second.GetSessionInfo().State);
        Assert.Equal(login.User, first.Login!.User);
        Assert.True(first.Login.IsActive);
        Assert.Equal(1, _module.LoginCalls);
    }

    [Fact]
    public void DisposingASession_NeverLogsOut()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session kept = login.OpenSession();

        login.OpenSession().Dispose();
        Slot.OpenSession().Dispose();

        Assert.Equal(0, _module.LogoutCalls);
        Assert.True(login.IsActive);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, kept.GetSessionInfo().State);
    }

    [Fact]
    public void LoginDisposedBeforeItsSessions_LogsOutAfterTheLast()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session first = login.OpenSession();
        using Pkcs11Session second = login.OpenSession();
        using Pkcs11Session observer = Slot.OpenSession();

        login.Dispose();
        Assert.False(login.IsActive);
        Assert.Equal(0, _module.LogoutCalls);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, first.GetSessionInfo().State);

        first.Dispose();
        Assert.Equal(0, _module.LogoutCalls);

        second.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
        Assert.Equal(CKS.CKS_RO_PUBLIC_SESSION, observer.GetSessionInfo().State);
    }

    [Fact]
    public void SlotSession_SeesLogin_ButDoesNotHoldIt()
    {
        using Pkcs11Session slotSession = Slot.OpenSession();
        Assert.Null(slotSession.Login);

        using (Pkcs11Login login = Slot.Login(TokenUser.User, _pin))
        using (login.OpenSession())
            Assert.Equal(CKS.CKS_RO_USER_FUNCTIONS, slotSession.GetSessionInfo().State);

        Assert.Equal(1, _module.LogoutCalls);
        Assert.Equal(CKS.CKS_RO_PUBLIC_SESSION, slotSession.GetSessionInfo().State);
    }

    [Fact]
    public void SlotOpenSession_DefaultsReadOnly()
    {
        using Pkcs11Session session = Slot.OpenSession();

        Assert.Equal(SessionAccess.ReadOnly, session.Access);
        Assert.False(Assert.Single(_module.OpenSessions).ReadWrite);
    }

    [Fact]
    public void LoginOpenSession_DefaultsReadWrite()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();

        Assert.Equal(SessionAccess.ReadWrite, session.Access);
        Assert.True(_module.OpenSessions[^1].ReadWrite);
    }

    [Fact]
    public void LoginUser_EmptyUsername_IsRefused()
    {
        Assert.Throws<ArgumentException>(() => Slot.LoginUser(TokenUser.User, _pin, ""));
        Assert.Equal(0, _module.LoginCalls);
    }

    [Fact]
    public void LoginUser_KeepsTheUsername_AndADifferentOneIsAnotherUser()
    {
        using Pkcs11Login alice = Slot.LoginUser(TokenUser.User, _pin, "alice");

        Assert.Equal("alice", alice.Username);
        Assert.Equal(TokenUser.User, alice.User);
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.LoginUser(TokenUser.User, _pin, "Alice"));
    }

    [Fact]
    public void LoginOpenSession_AfterTheLoginIsDisposed_IsRefused()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.Dispose();

        Assert.Throws<Pkcs11LoginEndedException>(() => login.OpenSession());
        Assert.Empty(_module.OpenSessions);
    }

    [Fact]
    public void TwoLibrariesOverOneModule_ShareTheLogin()
    {
        using Pkcs11Library second = _module.Load();

        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session other = SlotOf(second).OpenSession();
        Assert.Throws<Pkcs11AuthenticationException>(() => SlotOf(second).Login(TokenUser.User, _pin));
        Assert.True(SlotOf(second).TryShareLogin(TokenUser.User, out Pkcs11Login? share));
        using Pkcs11Login shared = share;

        Assert.Equal(CKS.CKS_RO_USER_FUNCTIONS, other.GetSessionInfo().State);
        Assert.True(shared.IsActive);
        Assert.Equal(1, _module.LoginCalls);
        Assert.Equal(2, _module.OpenSessions.Count); // one anchor, one session
    }

    [Fact]
    public void DisposingTheFirstLibrary_KeepsTheSecondsLogin()
    {
        using Pkcs11Library first = _module.Load();
        using Pkcs11Library second = _module.Load();

        using Pkcs11Login firstLogin = SlotOf(first).Login(TokenUser.User, _pin);
        Assert.True(SlotOf(second).TryShareLogin(TokenUser.User, out Pkcs11Login? share));
        using Pkcs11Login secondLogin = share;
        using Pkcs11Session secondSession = secondLogin.OpenSession();
        using Pkcs11Session observer = SlotOf(second).OpenSession();

        first.Dispose();

        Assert.False(firstLogin.IsActive);
        Assert.True(secondLogin.IsActive);
        Assert.Equal(0, _module.LogoutCalls);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, secondSession.GetSessionInfo().State);

        // Another share still takes the login the first library made; a second login is still refused, after
        // probing the anchor the first library opened.
        using (secondLogin.Share())
            Assert.Equal(1, _module.LoginCalls);
        Assert.Throws<Pkcs11AuthenticationException>(() => SlotOf(second).Login(TokenUser.User, _pin));

        secondLogin.Dispose();
        secondSession.Dispose();
        firstLogin.Dispose(); // released with its library: sends nothing

        Assert.Equal(1, _module.LogoutCalls);
        Assert.Equal(CKS.CKS_RO_PUBLIC_SESSION, observer.GetSessionInfo().State);
        Assert.Single(_module.OpenSessions); // the observer; the anchor closed
    }

    [Fact]
    public void LibraryDisposed_ItsLoginsBecomeInactive_AndTheModuleCanFinalize()
    {
        using Pkcs11Library library = _module.Load();
        using Pkcs11Login login = SlotOf(library).Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();

        library.Dispose();

        Assert.False(login.IsActive);
        Assert.Equal(1, _module.LogoutCalls);
        Assert.Empty(_module.OpenSessions);

        // Nothing of the disposed library holds the module: once the other load goes, it is finalized.
        _library.Dispose();
        Assert.Equal(1, _module.CallCount("C_Finalize"));

        // Leaked holders of a disposed library release nothing.
        session.Dispose();
        login.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
    }

    [Fact]
    public void WriteProtectedToken_ReadOnlySessionAndUserLogin_Work()
    {
        _module.WriteProtected = true;

        using Pkcs11Session slotSession = Slot.OpenSession();
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession(SessionAccess.ReadOnly);

        Assert.Equal(CKS.CKS_RO_USER_FUNCTIONS, session.GetSessionInfo().State);
        Assert.Equal(CKS.CKS_RO_USER_FUNCTIONS, slotSession.GetSessionInfo().State);
    }

    [Fact]
    public void AnchorIsNotClosedByTheOwningLibrarysDispose_WhileAnotherLibraryHolds()
    {
        using Pkcs11Library first = _module.Load();
        using Pkcs11Library second = _module.Load();

        using Pkcs11Login firstLogin = SlotOf(first).Login(TokenUser.User, _pin);
        ulong anchor = Assert.Single(_module.OpenSessions).Handle;
        Assert.True(SlotOf(second).TryShareLogin(TokenUser.User, out Pkcs11Login? share));
        using Pkcs11Login secondLogin = share;

        first.Dispose();

        Assert.Equal(anchor, Assert.Single(_module.OpenSessions).Handle);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
        Assert.Equal(0, _module.CallCount("C_Finalize"));

        secondLogin.Dispose();

        Assert.Empty(_module.OpenSessions);
        Assert.Equal(1, _module.LogoutCalls);
    }

    [Fact]
    public void LibraryDispose_ClosesItsSlotSessions()
    {
        using Pkcs11Library library = _module.Load();
        using Pkcs11Session session = SlotOf(library).OpenSession();

        library.Dispose();

        Assert.Empty(_module.OpenSessions);
        session.Dispose();
    }

    [Fact]
    public async Task LastLogout_WaitsForAnOperationInFlightOnAnotherSession()
    {
        using var inSign = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        int logoutsWhileSigning = -1;
        _module.DuringSign = () =>
        {
            inSign.Set();
            release.Wait(Generous);
            logoutsWhileSigning = _module.LogoutCalls;
        };

        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session slotSession = Slot.OpenSession();

        Task signing = Task.Run(() => Sign(slotSession), TestContext.Current.CancellationToken);
        Assert.True(inSign.Wait(Generous, TestContext.Current.CancellationToken), "C_Sign was never reached");

        // The release returns at once, the logout left pending for the sign in flight.
        login.Dispose();
        TokenLoginRecord record = slotSession.Core.LoginRecord;
        Assert.True(record.IsLogoutPending);
        Assert.Equal(0, _module.LogoutCalls);

        release.Set();
        await signing;
        Assert.False(record.IsLogoutPending);

        Assert.Equal(0, logoutsWhileSigning);
        Assert.Equal(1, _module.LogoutCalls);
    }

    [Fact]
    public void DisposingTheLastHolderSession_InsideAnOperation_DefersTheLogout()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        login.Dispose();

        using (session.Core.AcquireExclusive())
        {
            session.Dispose();
            Assert.Equal(0, _module.LogoutCalls);
            Assert.True(session.Core.LoginRecord.IsLogoutPending);
        }

        Assert.Equal(1, _module.LogoutCalls);
        Assert.Empty(_module.OpenSessions);
    }

    // K9. The Security Officer's login is not shared from the slot (it can set the user PIN): only by handing its
    // Pkcs11Login on. A session exposes its login as a read-only view.
    [Fact]
    public void TryShareLogin_SecurityOfficer_IsRefused_ShareThroughTheLoginWorks()
    {
        using Pkcs11Login so = Slot.Login(TokenUser.SecurityOfficer, _pin);

        Assert.Throws<ArgumentException>(() => Slot.TryShareLogin(TokenUser.SecurityOfficer, out _));
        using Pkcs11Login shared = so.Share();
        Assert.True(shared.IsActive);

        using Pkcs11Session session = so.OpenSession(SessionAccess.ReadWrite);
        Pkcs11LoginInfo info = Assert.IsType<Pkcs11LoginInfo>(session.Login);
        Assert.Equal(TokenUser.SecurityOfficer, info.User);
        Assert.True(info.IsActive);
        Assert.False(session.IsLent);
    }

    // Q5. ShareOrLogin through the slot: the first call logs in (PIN source called once), the next shares.
    [Fact]
    public void ShareOrLogin_FirstLogsIn_NextShares()
    {
        int asked = 0;
        using Pkcs11Login first = Slot.ShareOrLogin(() => { asked++; return new SecurePin(_module.ExpectedPin); });
        using Pkcs11Login second = Slot.ShareOrLogin(() => { asked++; return new SecurePin(_module.ExpectedPin); });

        Assert.Equal(1, asked);
        Assert.Equal(1, _module.LoginCalls);
        Assert.True(second.IsActive);
        Assert.Equal(TokenUser.User, second.User);
    }

    // K13. A slot found by a lookup remembers its token: a token swapped in before the login does not receive the PIN.
    [Fact]
    public void SlotSelectedByLabel_TokenSwappedBeforeLogin_RefusedWithNoPinSent()
    {
        Pkcs11Slot slot = _library.GetSlotByTokenLabel(LoginTokenModule.TokenLabel);
        _module.Label = "another-token";

        var ex = Assert.Throws<Pkcs11TokenException>(() => slot.Login(TokenUser.User, _pin));

        Assert.Equal(CKR.CKR_TOKEN_NOT_RECOGNIZED, ex.ReturnValue);
        Assert.Equal(0, _module.LoginCalls);
        Assert.Empty(_module.OpenSessions);
    }

    // Q2. Pkcs11Login.LoggedOut completes once the token is logged out: Dispose may return before, while an operation is
    // in flight.
    [Fact]
    public void LoggedOut_CompletesWhenTheDeferredLogoutIsSent()
    {
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Task loggedOut = login.LoggedOut;
        TokenLoginRecord record = Slot.LoginRecord;
        using (record.EnterOperation())
        {
            login.Dispose();
            Assert.False(loggedOut.IsCompleted);
        }
        Assert.True(loggedOut.IsCompletedSuccessfully);
        Assert.Equal(1, _module.LogoutCalls);
    }
}
