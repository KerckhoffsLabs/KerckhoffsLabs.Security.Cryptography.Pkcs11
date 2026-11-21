using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Where a refused PIN is remembered, and what forgets it: every call that sends a PIN the token checks (a login, the
/// old PIN of <c>C_SetPIN</c>, the SO PIN of <c>C_InitToken</c>, a context login) is refused before the module with a
/// PIN the token refused before for the same purpose; a change of one user's PIN leaves the other's refusals; a key with
/// a PIN of its own is told from a stale PIN; and sends are one at a time per slot, so threads that send the same stale
/// PIN at once spend one retry.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class RefusedPinScopeTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    private const string AlwaysAuthenticateEc = "aa-ec";
    private const string QualifiedEc = "qes-ec";
    private static readonly Mechanism Ecdsa = new(CKM.CKM_ECDSA_SHA256);
    private static readonly byte[] SignaturePin = "778899"u8.ToArray();

    private readonly CapturingLogger _logger = new();
    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public RefusedPinScopeTests()
    {
        var alwaysAuthenticate = new Dictionary<CKA, byte[]> { [CKA.CKA_ALWAYS_AUTHENTICATE] = [1] };
        _module.AddObject(CKO.CKO_PRIVATE_KEY, AlwaysAuthenticateEc, isPrivate: true, keyType: CKK.CKK_EC, more: alwaysAuthenticate);
        _module.AddObject(CKO.CKO_PRIVATE_KEY, QualifiedEc, isPrivate: true, keyType: CKK.CKK_EC,
            more: new Dictionary<CKA, byte[]>(alwaysAuthenticate));
        _module.KeyPins[QualifiedEc] = SignaturePin;
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

    private static ContextAuthentication Pin(byte[] pin) => ContextAuthentication.FromPinSource(_ => new SecurePin(pin));

    // ---- C_SetPIN ----

    // The old PIN is checked by the token at the cost of a retry: one it refused is not sent again.
    [Fact]
    public void SetPin_WrongOldPin_SentOnce_ThenRefusedBeforeTheModule()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        using var wrong = new SecurePin("0000");
        using var next = new SecurePin("5678");

        Assert.Throws<Pkcs11AuthenticationException>(() => session.SetPinWithPin(wrong, next));
        var again = Assert.Throws<Pkcs11AuthenticationException>(() => session.SetPinWithPin(wrong, next));

        Assert.Equal(CKR.CKR_PIN_INCORRECT, again.ReturnValue);
        Assert.Contains("refused this old PIN before", again.Message, StringComparison.Ordinal);
        Assert.Equal(1, _module.WrongPins(CKU.CKU_USER));
    }

    // A change of the user's PIN says nothing of the SO's: a PIN refused for the SO stays refused.
    [Fact]
    public void SetPin_OfTheUser_SoRefusalStands()
    {
        _module.SoPin = "9999"u8.ToArray();
        using (var wrongSo = new SecurePin("1111"))
            Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.SecurityOfficer, wrongSo));

        using (Pkcs11Login login = Slot.Login(TokenUser.User, _pin))
        using (Pkcs11Session session = login.OpenSession())
        using (var next = new SecurePin("5678"))
            session.SetPinWithPin(_pin, next);

        using var stale = new SecurePin("1111");
        var ex = Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.SecurityOfficer, stale));
        Assert.Contains("refused this PIN before", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, _module.WrongPins(CKU.CKU_SO));
    }

    // A PIN refused before the change and set by it is the PIN now: it is sent again.
    [Fact]
    public void SetPin_ToAPinRefusedBefore_ItIsSentOnceItIsThePin()
    {
        using var newPin = new SecurePin("5678");
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, newPin));

        using (Pkcs11Login login = Slot.Login(TokenUser.User, _pin))
        using (Pkcs11Session session = login.OpenSession())
            session.SetPinWithPin(_pin, newPin);

        using Pkcs11Login after = Slot.Login(TokenUser.User, newPin);
        Assert.True(after.IsActive);
    }

    // ---- C_InitToken ----

    // The SO PIN of a token initialized before is checked at the cost of an SO retry: one refused is not sent again.
    [Fact]
    public void InitToken_WrongSoPin_SentOnce_ThenRefusedBeforeTheModule()
    {
        _module.SoPin = "9999"u8.ToArray();
        using var wrong = new SecurePin("1111");

        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.InitTokenWithPin(wrong, "fresh"));
        var again = Assert.Throws<Pkcs11AuthenticationException>(() => Slot.InitTokenWithPin(wrong, "fresh"));

        Assert.Contains("refused this Security Officer PIN before", again.Message, StringComparison.Ordinal);
        Assert.Equal(1, _module.WrongPins(CKU.CKU_SO));
        Assert.Equal(LoginTokenModule.TokenLabel, Slot.GetTokenInfo().Label);
    }

    // The usual provisioning flow on a slot found by its label: initialize the token under a new label, then log the SO
    // in through the same slot to set the user PIN. The slot takes the token as it is now, so the login is not refused
    // as made to another token.
    [Fact]
    public void InitToken_Relabels_SlotSelectedByLabel_SoLoginWorks()
    {
        Pkcs11Slot slot = _library.GetSlotByTokenLabel(LoginTokenModule.TokenLabel);

        slot.InitTokenWithPin(_pin, "relabelled");

        using Pkcs11Login login = slot.Login(TokenUser.SecurityOfficer, _pin);
        Assert.True(login.IsActive);
        Assert.Equal("relabelled", slot.GetTokenInfo().Label);
    }

    // ---- Context logins ----

    // A key with a PIN of its own (a qualified signature key) refuses the user's PIN, which the token accepted for the
    // login held: that refusal is the key's. The user's PIN is still sent for the other keys, and not for that one.
    [Fact]
    public void ContextLogin_KeyWithItsOwnPin_RefusalIsThatKeys_OtherKeysStillGetTheUserPin()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = Pin(_module.ExpectedPin);
        using Pkcs11Key qualified = session.OpenKey(QualifiedEc);
        using Pkcs11Key ordinary = session.OpenKey(AlwaysAuthenticateEc);

        Assert.Throws<Pkcs11AuthenticationException>(() => qualified.Sign(Ecdsa, "data"u8));
        Assert.NotEmpty(ordinary.Sign(Ecdsa, "data"u8));

        _module.ClearCallLog();
        var again = Assert.Throws<Pkcs11AuthenticationException>(() => qualified.Sign(Ecdsa, "data"u8));
        Assert.Contains("refused this PIN before", again.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(LoginTokenModule.ContextLogin, _module.CallLog);

        session.ContextAuthentication = ContextAuthentication.FromPinSource(
            key => new SecurePin(key.Label == QualifiedEc ? SignaturePin : _module.ExpectedPin));
        Assert.NotEmpty(qualified.Sign(Ecdsa, "data"u8));
        Assert.NotEmpty(ordinary.Sign(Ecdsa, "data"u8));
    }

    // A login made on the pinpad leaves the user's PIN unknown: sent by mistake to a key with a PIN of its own, it is
    // taken for a stale one and refused for every key, and, the user's login PIN and the context PIN being one purpose,
    // for the user's login too: the documented cost, which fails safe. ForgetRefusedPins lets it be sent again.
    [Fact]
    public void ContextLogin_UserPinRefusedAfterPinpadLogin_TakenForStale_UntilForgotten()
    {
        _module.ProtectedAuthenticationPath = true;
        using (Pkcs11Login pinpad = Slot.Login(TokenUser.User, LoginCredential.Pinpad))
        using (Pkcs11Session session = pinpad.OpenSession())
        {
            session.ContextAuthentication = Pin(_module.ExpectedPin);
            using Pkcs11Key qualified = session.OpenKey(QualifiedEc);
            using Pkcs11Key ordinary = session.OpenKey(AlwaysAuthenticateEc);
            Assert.Throws<Pkcs11AuthenticationException>(() => qualified.Sign(Ecdsa, "data"u8));
            var stale = Assert.Throws<Pkcs11AuthenticationException>(() => ordinary.Sign(Ecdsa, "data"u8));
            Assert.Contains("refused this PIN before", stale.Message, StringComparison.Ordinal);
        }
        int loginCalls = _module.LoginCalls;

        var refused = Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, _pin));

        Assert.Contains("refused this PIN before", refused.Message, StringComparison.Ordinal);
        Assert.Equal(loginCalls, _module.LoginCalls);
        Slot.ForgetRefusedPins();
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Assert.True(login.IsActive);
    }

    // The user's login PIN and the token's context PINs are one purpose: a stale secret refused as one is not sent as the
    // other, in either order. One retry in all.
    [Fact]
    public void StalePin_RefusedAsUserLogin_NotSentAsContextPin_AndTheReverse()
    {
        using (var stale = new SecurePin("4321"))
            Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, stale));
        using (Pkcs11Login login = Slot.Login(TokenUser.User, _pin))
        using (Pkcs11Session session = login.OpenSession())
        {
            session.ContextAuthentication = Pin("4321"u8.ToArray());
            using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
            _module.ClearCallLog();
            Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));
            Assert.DoesNotContain(LoginTokenModule.ContextLogin, _module.CallLog);

            session.ContextAuthentication = Pin("8765"u8.ToArray());
            Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8)); // sent, refused: stale
        }
        int loginCalls = _module.LoginCalls;
        using var other = new SecurePin("8765");

        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, other));

        Assert.Equal(loginCalls, _module.LoginCalls);
    }

    // A PIN the token never accepted under the login is a stale one: refused for one key, it is not sent for any.
    [Fact]
    public void ContextLogin_StalePin_RefusedForEveryKey()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = Pin("4321"u8.ToArray());
        using Pkcs11Key qualified = session.OpenKey(QualifiedEc);
        using Pkcs11Key ordinary = session.OpenKey(AlwaysAuthenticateEc);

        Assert.Throws<Pkcs11AuthenticationException>(() => qualified.Sign(Ecdsa, "data"u8));
        _module.ClearCallLog();

        var ex = Assert.Throws<Pkcs11AuthenticationException>(() => ordinary.Sign(Ecdsa, "data"u8));

        Assert.Contains("refused this PIN before", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(LoginTokenModule.ContextLogin, _module.CallLog);
    }

    // Sessions that send the same stale context PIN at once: the first is sent while the others wait their turn, then
    // find it refused. One retry spent, not one per session. On a module without C_SessionCancel, no operation is left
    // active: the first, which the token refused, is ended by a length query and its session signs again; those that
    // waited sent no context login, so nothing says their operations are held back, and their sessions are closed.
    [Fact]
    public void ContextLogins_ConcurrentStalePin_OneRetry()
    {
        _module.SupportsSessionCancel = false;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.ContextAuthentication = Pin("4321"u8.ToArray());
        Pkcs11Session[] sessions = [login.OpenSession(), login.OpenSession(), login.OpenSession()];
        Pkcs11Key[] keys = [.. sessions.Select(s => s.OpenKey(AlwaysAuthenticateEc))];
        using var inLogin = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        int logins = 0;
        _module.DuringLogin = _ =>
        {
            if (Interlocked.Increment(ref logins) != 1)
                return;
            inLogin.Set();
            release.Wait(Timeout, TestContext.Current.CancellationToken);
        };
        try
        {
            BackgroundWork first = BackgroundWork.Run(() => keys[0].Sign(Ecdsa, "data"u8));
            Assert.True(inLogin.Wait(Timeout, TestContext.Current.CancellationToken));
            BackgroundWork[] others = [.. keys.Skip(1).Select(key => BackgroundWork.Run(() => key.Sign(Ecdsa, "data"u8)))];
            Assert.All(others, other => Assert.True(other.WaitUntilBlocked(Timeout), $"did not wait its turn: {other.Failure}"));

            release.Set();

            Assert.All([first, .. others], work => Assert.True(work.Join(Timeout)));
            Assert.All([first, .. others], work => Assert.IsType<Pkcs11AuthenticationException>(work.Failure));
            Assert.Single(_module.ContextPins);
            Assert.All(sessions, session => Assert.False(_module.HasActiveOperation(session.Core.SessionId)));
            sessions[0].ContextAuthentication = Pin(_module.ExpectedPin);
            Assert.NotEmpty(keys[0].Sign(Ecdsa, "data"u8));
            Assert.All(keys.Skip(1), key => Assert.Contains("closed to end an operation",
                Assert.Throws<Pkcs11SessionException>(() => key.Sign(Ecdsa, "data"u8)).Message, StringComparison.Ordinal));
        }
        finally
        {
            release.Set();
            foreach (Pkcs11Key key in keys)
                key.Dispose();
            foreach (Pkcs11Session session in sessions)
                session.Dispose();
        }
    }

    // A v2.40 module (no C_SessionCancel) that answers the length query of an operation whose context PIN it refused
    // with a length and CKR_OK, keeping the operation (OpenSC: its context login only re-checks the user's PIN, so a
    // full call could sign): the full call is never sent; the session is closed, which ends the operation with no
    // output, and refuses later calls saying so. The login stands.
    [Fact]
    public void ContextLogin_PinRefused_LengthAnswered_NoFullCall_SessionClosed()
    {
        _module.SupportsSessionCancel = false;
        _module.AnswersLengthQueryUnauthenticated = true;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = Pin("4321"u8.ToArray());
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        ulong sessionId = session.Core.SessionId;
        _module.ClearCallLog();

        Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Equal(1, _module.CallLog.Count(call => call == "C_Sign")); // the length query only
        Assert.False(_module.HasActiveOperation(sessionId));
        Assert.DoesNotContain(_module.OpenSessions, open => open.Handle == sessionId);
        Assert.Throws<Pkcs11SessionException>(() => key.Sign(Ecdsa, "data"u8));
        Assert.True(login.IsActive);
        using Pkcs11Session next = login.OpenSession();
        next.ContextAuthentication = Pin(_module.ExpectedPin);
        using Pkcs11Key again = next.OpenKey(AlwaysAuthenticateEc);
        Assert.NotEmpty(again.Sign(Ecdsa, "data"u8));
    }

    // The length query that would end a refused context login's operation answers something other than
    // CKR_USER_NOT_LOGGED_IN (a device error, which ends nothing for sure): the operation is not taken as ended, and the
    // session is closed, so its next call says why rather than meeting a bare CKR_OPERATION_ACTIVE.
    [Fact]
    public void ContextLogin_PinRefused_LengthQueryFails_SessionClosed()
    {
        _module.SupportsSessionCancel = false;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = Pin("4321"u8.ToArray());
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        ulong sessionId = session.Core.SessionId;
        _module.FailNext("C_Sign", CKR.CKR_DEVICE_ERROR);

        Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.DoesNotContain(_module.OpenSessions, open => open.Handle == sessionId);
        var closed = Assert.Throws<Pkcs11SessionException>(() => key.Sign(Ecdsa, "data"u8));
        Assert.Contains("closed to end an operation", closed.Message, StringComparison.Ordinal);
    }

    // A context PIN whose form the token judged (CKR_PIN_LEN_RANGE, which OpenSC answers on the host, without the card):
    // remembered as refused, but no evidence the operation is held back, so it is not even queried: on a v2.40 module
    // the session is closed.
    [Fact]
    public void ContextLogin_PinLenRange_NoSessionCancel_NotQueried_SessionClosed()
    {
        _module.SupportsSessionCancel = false;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = Pin("12"u8.ToArray());
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        ulong sessionId = session.Core.SessionId;
        _module.ClearCallLog();
        _module.FailNext("C_Login", CKR.CKR_PIN_LEN_RANGE);

        Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.DoesNotContain("C_Sign", _module.CallLog);
        Assert.DoesNotContain(_module.OpenSessions, open => open.Handle == sessionId);
        _module.ClearCallLog();
        using Pkcs11Session next = login.OpenSession();
        next.ContextAuthentication = Pin("12"u8.ToArray());
        using Pkcs11Key again = next.OpenKey(AlwaysAuthenticateEc);
        var refused = Assert.Throws<Pkcs11AuthenticationException>(() => again.Sign(Ecdsa, "data"u8));
        Assert.Contains("refused this PIN before", refused.Message, StringComparison.Ordinal);
    }

    // ---- The PIN source and logins ----

    // A ShareOrLogin PIN source runs outside the token's login transition: one that waits for a thread logging in to the
    // same token does not hang, and the login that thread made is shared, the PIN disposed unsent.
    [Fact]
    public void ShareOrLogin_PinSourceWaitsForAThreadThatLogsIn_LoginShared()
    {
        Pkcs11Login? other = null;
        SecurePin? handedOut = null;
        Pkcs11Slot slot = Slot;

        using Pkcs11Login shared = slot.ShareOrLogin(LoginCredential.FromPinSource(() =>
        {
            var thread = new Thread(() => other = slot.Login(TokenUser.User, _pin));
            thread.Start();
            Assert.True(thread.Join(Timeout));
            handedOut = new SecurePin(_module.ExpectedPin);
            return handedOut;
        }));

        using (other)
        {
            Assert.True(shared.IsActive);
            Assert.Equal(1, _module.LoginCalls);
            Assert.True(handedOut!.IsDisposed);
        }
    }

    // A login from inside an operation on another token, while this token's logout waits for an operation in flight:
    // refused rather than waited, since a logout pending on the other token could be waiting for this thread.
    [Fact]
    public void Login_FromInsideAnOperationOnAnotherToken_LogoutPending_Refused()
    {
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        TokenLoginRecord record = Slot.LoginRecord;
        using var inOperation = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        BackgroundWork operation = BackgroundWork.Run(() =>
        {
            using (record.EnterOperation())
            {
                inOperation.Set();
                release.Wait(Timeout, TestContext.Current.CancellationToken);
            }
        });
        try
        {
            Assert.True(inOperation.Wait(Timeout, TestContext.Current.CancellationToken));
            login.Dispose(); // the logout waits for the operation in flight

            var otherToken = new TokenLoginRecord((NativeCULong)99UL);
            using (otherToken.EnterOperation())
            {
                var ex = Assert.Throws<InvalidOperationException>(() => Slot.Login(TokenUser.User, _pin));
                Assert.Contains("on this token or another", ex.Message, StringComparison.Ordinal);
            }
        }
        finally
        {
            release.Set();
            Assert.True(operation.Join(Timeout));
        }
        Assert.Equal(1, _module.LogoutCalls);
    }

    // Ending a login never waits for its session's lock: a module that reports the login gone while that session is
    // lent and in an operation on another thread ends it at once, and the session closes once the operation lets go.
    [Fact]
    public void LoginEnded_WhileItsLentSessionIsInAnOperation_DoesNotWait()
    {
        _module.MaxSessions = 1;
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Pkcs11Session lent = login.OpenSession();
        using var inSign = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        _module.DuringSign = () =>
        {
            _module.DuringSign = null;
            inSign.Set();
            release.Wait(Timeout, TestContext.Current.CancellationToken);
        };
        using Pkcs11Key key = lent.OpenKey(AlwaysAuthenticateEc);
        lent.ContextAuthentication = Pin(_module.ExpectedPin);
        BackgroundWork sign = BackgroundWork.Run(() => key.Sign(Ecdsa, "data"u8));
        try
        {
            Assert.True(inSign.Wait(Timeout, TestContext.Current.CancellationToken));

            BackgroundWork end = BackgroundWork.Run(() => Slot.LoginRecord.MarkEnded(CKR.CKR_DEVICE_ERROR));

            Assert.True(end.Join(Timeout), "ending the login waited for the lent session's operation");
            Assert.Null(end.Failure);
            Assert.False(login.IsActive);
        }
        finally
        {
            release.Set();
            Assert.True(sign.Join(Timeout));
            lent.Dispose();
            login.Dispose();
        }
        SpinWait.SpinUntil(() => _module.OpenSessions.Count == 0, Timeout);
        Assert.Empty(_module.OpenSessions);
    }
}

/// <summary>
/// <see cref="Pkcs11LibraryOptions.RefusedPinLifetime"/>: a refusal older than it no longer keeps the PIN from the token.
/// A class of its own, for a library loaded with the option.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class RefusedPinLifetimeTests
{
    // With RefusedPinLifetime, a refusal older than it no longer keeps the PIN from the token. The refusals' clock is
    // set, not waited for.
    [Fact]
    public void RefusedPinLifetime_Passed_PinSentAgain()
    {
        using var module = new LoginTokenModule();
        using Pkcs11Library library = module.Load(new Pkcs11LibraryOptions { RefusedPinLifetime = TimeSpan.FromMinutes(5) });
        Pkcs11Slot slot = Assert.Single(library.GetSlotList());
        long now = 1_000_000;
        slot.LoginRecord.RefusedPins.Clock = () => now;
        using var wrong = new SecurePin("0000");

        Assert.Throws<Pkcs11AuthenticationException>(() => slot.Login(TokenUser.User, wrong));
        now += (long)TimeSpan.FromMinutes(5).TotalMilliseconds - 1;
        var refused = Assert.Throws<Pkcs11AuthenticationException>(() => slot.Login(TokenUser.User, wrong));
        Assert.Contains("refused this PIN before", refused.Message, StringComparison.Ordinal);
        Assert.Equal(1, module.LoginCalls);

        now += 1;

        Assert.Throws<Pkcs11AuthenticationException>(() => slot.Login(TokenUser.User, wrong));
        Assert.Equal(2, module.LoginCalls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void RefusedPinLifetime_NotPositive_Refused(int milliseconds)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => new Pkcs11LibraryOptions { RefusedPinLifetime = TimeSpan.FromMilliseconds(milliseconds) });
        Assert.Equal(nameof(Pkcs11LibraryOptions.RefusedPinLifetime), ex.ParamName);
    }
}
