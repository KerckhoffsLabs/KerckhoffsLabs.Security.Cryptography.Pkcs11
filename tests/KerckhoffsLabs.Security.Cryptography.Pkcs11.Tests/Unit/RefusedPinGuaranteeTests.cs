using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The refused-PIN guarantees, each by a test that fails when it breaks: refusals outlive the module's
/// <c>C_Finalize</c>; are the token's, told by its bytes; are kept per user and username; count every refusal code a
/// login gets; are forgotten only for the PIN set; cost one retry when threads send the same stale PIN at once, for
/// logins and <c>C_SetPIN</c> as for context logins; and a token that cannot be read is not sent the PIN. Also: a slow
/// <c>ShareOrLogin</c> PIN source does not let the login land inside an operation started while it ran, and
/// <c>InitToken</c> never reaches a token swapped in since the slot was looked up.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class RefusedPinGuaranteeTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    private readonly LoginTokenModule _module = new();
    private Pkcs11Library _library;
    private readonly SecurePin _pin;

    public RefusedPinGuaranteeTests()
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

    private Pkcs11Slot Slot => Assert.Single(_library.GetSlotList());

    private static SecurePin Wrong() => new("9999");

    // Code that loads the module, logs in and unloads it on every request: each unload runs C_Finalize, which ends every
    // login, yet the refusal stays, so a stale PIN is sent once in all.
    [Fact]
    public void Refusal_OutlivesTheModulesFinalize_AReloadDoesNotSendIt()
    {
        using (SecurePin wrong = Wrong())
            Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, wrong));
        _library.Dispose();
        _library = _module.Load();

        using SecurePin again = Wrong();
        var refused = Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, again));

        Assert.Contains("refused this PIN before", refused.Message, StringComparison.Ordinal);
        Assert.Equal(1, _module.LoginCalls);
    }

    // A token whose information cannot be read is not sent the PIN: it could be neither checked nor remembered.
    [Fact]
    public void Login_TokenInfoUnreadable_PinNotSent()
    {
        _module.FailNext("C_GetTokenInfo", CKR.CKR_DEVICE_ERROR);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => Slot.Login(TokenUser.User, _pin));

        Assert.Equal(CKR.CKR_DEVICE_ERROR, ex.ReturnValue);
        Assert.Equal(0, _module.LoginCalls);
    }

    // A refusal is the token's, told by the bytes it reports: a token swapped in whose label differs only in bytes that
    // are not UTF-8 (both decode to U+FFFD) is another token, sent the PIN; and a slot selected by the first refuses a
    // login once it holds the second, before any PIN is sent.
    [Fact]
    public void TokenIdentity_IsTheBytes_NotTheDecodedText()
    {
        _module.LabelBytes = [0xFF, (byte)'a'];
        Pkcs11Slot selected = _library.GetSlot(token => token.Label == "�a");
        using (SecurePin wrong = Wrong())
            Assert.Throws<Pkcs11AuthenticationException>(() => selected.Login(TokenUser.User, wrong));
        Assert.Equal(1, _module.LoginCalls);

        _module.LabelBytes = [0xFE, (byte)'a'];

        var swapped = Assert.Throws<Pkcs11TokenException>(() => selected.Login(TokenUser.User, _pin));
        Assert.Equal(CKR.CKR_TOKEN_NOT_RECOGNIZED, swapped.ReturnValue);
        Assert.Equal(1, _module.LoginCalls);
        using (SecurePin wrong = Wrong())
            Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, wrong));
        Assert.Equal(2, _module.LoginCalls); // another token: sent
    }

    // Refusals are per user and username: one refused for alice is still sent for bob and for the plain user.
    [Fact]
    public void Refusal_IsTheUsernames()
    {
        using SecurePin wrong = Wrong();
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, wrong, "alice"));
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, wrong, "alice"));
        Assert.Equal(1, _module.LoginCalls);

        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, wrong, "bob"));
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, wrong));
        Assert.Equal(3, _module.LoginCalls);
    }

    // CKR_PIN_LEN_RANGE and CKR_PIN_INVALID refuse a login's PIN as CKR_PIN_INCORRECT does: not sent again.
    [Theory]
    [InlineData(CKR.CKR_PIN_LEN_RANGE)]
    [InlineData(CKR.CKR_PIN_INVALID)]
    public void Login_RefusedWithAnyPinCode_NotSentAgain(CKR code)
    {
        using var odd = new SecurePin("12");
        _module.FailNext("C_Login", code);
        Assert.Equal(code, Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, odd)).ReturnValue);

        var again = Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, odd));

        Assert.Contains("refused this PIN before", again.Message, StringComparison.Ordinal);
        Assert.Equal(1, _module.LoginCalls);
    }

    // C_InitPIN sets the user's PIN: a refusal of the new PIN is forgotten; one of another PIN stands.
    [Fact]
    public void InitUserPin_ForgetsTheNewPinsRefusal_OthersStand()
    {
        using var next = new SecurePin("5678");
        using SecurePin other = Wrong();
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, next));
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, other));

        using (Pkcs11Login so = Slot.Login(TokenUser.SecurityOfficer, _pin))
            so.InitUserPinWithPin(next);

        using (Pkcs11Login user = Slot.Login(TokenUser.User, next))
            Assert.True(user.IsActive);
        int loginCalls = _module.LoginCalls;
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, other));
        Assert.Equal(loginCalls, _module.LoginCalls);
    }

    // A PIN changed on the pinpad may be any PIN: that user's refusals are forgotten, the SO's stand.
    [Fact]
    public void SetPinWithPinpad_ForgetsThatUsersRefusals_TheSosStand()
    {
        _module.ProtectedAuthenticationPath = true;
        _module.SoPin = "8888"u8.ToArray();
        using SecurePin wrong = Wrong();
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, wrong));
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.SecurityOfficer, wrong));

        using (Pkcs11Login login = Slot.Login(TokenUser.User, _pin))
        using (Pkcs11Session session = login.OpenSession())
            session.SetPinWithPinpad();

        int loginCalls = _module.LoginCalls;
        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, wrong));
        Assert.Equal(loginCalls + 1, _module.LoginCalls); // sent again
        var so = Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.SecurityOfficer, wrong));
        Assert.Contains("refused this PIN before", so.Message, StringComparison.Ordinal);
        Assert.Equal(loginCalls + 1, _module.LoginCalls);
    }

    // Threads that log in with the same stale PIN at once: the first is sent while the others wait their turn (behind
    // the slot's transition semaphore, which orders logins), then find it refused. One retry spent.
    [Fact]
    public void ShareOrLogin_ConcurrentStalePin_OneRetry()
    {
        _module.LoginLockAfter = 3;
        using var inLogin = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        _module.DuringLogin = _ =>
        {
            _module.DuringLogin = null;
            inLogin.Set();
            release.Wait(TimeSpan.FromSeconds(60));
        };
        Pkcs11Slot slot = Slot;
        BackgroundWork first = BackgroundWork.Run(() => slot.ShareOrLogin(LoginCredential.FromPinSource(Wrong)).Dispose());
        Assert.True(inLogin.Wait(Timeout, TestContext.Current.CancellationToken));
        BackgroundWork[] others = [.. Enumerable.Range(0, 2).Select(_ => BackgroundWork.Run(() => slot.ShareOrLogin(LoginCredential.FromPinSource(Wrong)).Dispose()))];
        try
        {
            Assert.All(others, other => Assert.True(other.WaitUntilBlocked(Timeout), $"did not wait its turn: {other.Failure}"));
        }
        finally
        {
            release.Set();
        }

        Assert.All([first, .. others], work => Assert.True(work.Join(Timeout)));
        Assert.All([first, .. others], work => Assert.IsType<Pkcs11AuthenticationException>(work.Failure));
        Assert.Equal(1, _module.WrongPins(CKU.CKU_USER));
        Assert.Equal(1, _module.LoginCalls);
    }

    // A login and a C_SetPIN with the same stale PIN at once: no transition orders them, only the slot's PIN sends
    // (RefusedPins.Serialized), so the C_SetPIN waits for the login's answer, finds the PIN refused, and is not sent.
    [Fact]
    public void LoginAndSetPin_ConcurrentStalePin_OneRetry()
    {
        _module.LoginLockAfter = 3;
        using Pkcs11Session session = Slot.OpenSession(SessionAccess.ReadWrite);
        using var inLogin = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        int setPins = 0;
        _module.DuringSetPin = () => setPins++;
        _module.DuringLogin = _ =>
        {
            _module.DuringLogin = null;
            inLogin.Set();
            release.Wait(TimeSpan.FromSeconds(60));
        };
        Pkcs11Slot slot = Slot;
        BackgroundWork login = BackgroundWork.Run(() =>
        {
            using SecurePin stale = Wrong();
            slot.Login(TokenUser.User, stale).Dispose();
        });
        Assert.True(inLogin.Wait(Timeout, TestContext.Current.CancellationToken));
        BackgroundWork setPin = BackgroundWork.Run(() =>
        {
            using SecurePin stale = Wrong();
            using var next = new SecurePin("24681357");
            session.SetPinWithPin(stale, next);
        });
        try
        {
            Assert.True(setPin.WaitUntilBlocked(Timeout), $"did not wait its turn: {setPin.Failure}");
        }
        finally
        {
            release.Set();
        }

        Assert.All([login, setPin], work => Assert.True(work.Join(Timeout)));
        Assert.All([login, setPin], work => Assert.IsType<Pkcs11AuthenticationException>(work.Failure));
        Assert.Equal(0, setPins);
        Assert.Equal(1, _module.WrongPins(CKU.CKU_USER));
    }

    // Sessions that change the PIN with the same stale old PIN at once: one C_SetPIN reaches the token.
    [Fact]
    public void SetPin_ConcurrentStaleOldPin_OneRetry()
    {
        _module.LoginLockAfter = 3;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session one = login.OpenSession();
        using Pkcs11Session two = login.OpenSession();
        using var inSetPin = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        _module.DuringSetPin = () =>
        {
            _module.DuringSetPin = null;
            inSetPin.Set();
            release.Wait(TimeSpan.FromSeconds(60));
        };
        using SecurePin stale = Wrong();
        using var next = new SecurePin("5678");
        BackgroundWork first = BackgroundWork.Run(() => one.SetPinWithPin(stale, next));
        Assert.True(inSetPin.Wait(Timeout, TestContext.Current.CancellationToken));
        BackgroundWork second = BackgroundWork.Run(() => two.SetPinWithPin(stale, next));
        try
        {
            Assert.True(second.WaitUntilBlocked(Timeout), $"did not wait its turn: {second.Failure}");
        }
        finally
        {
            release.Set();
        }

        Assert.True(first.Join(Timeout));
        Assert.True(second.Join(Timeout));
        Assert.IsType<Pkcs11AuthenticationException>(first.Failure);
        Assert.Contains("refused this old PIN before", Assert.IsType<Pkcs11AuthenticationException>(second.Failure).Message,
            StringComparison.Ordinal);
        Assert.Equal(1, _module.WrongPins(CKU.CKU_USER));
    }

    // A ShareOrLogin PIN source that takes its time while an operation starts on another session: the login waits for
    // that operation, which is in flight when the PIN is in hand, rather than landing inside it.
    [Fact]
    public void ShareOrLogin_SlowPinSource_OperationStartedMeanwhile_IsWaitedFor()
    {
        using Pkcs11Session other = Slot.OpenSession(SessionAccess.ReadOnly);
        TokenLoginRecord record = Slot.LoginRecord;
        using var inSearch = new ManualResetEventSlim();
        using var releaseSearch = new ManualResetEventSlim();
        _module.DuringFind = () =>
        {
            _module.DuringFind = null;
            inSearch.Set();
            releaseSearch.Wait(TimeSpan.FromSeconds(60));
        };
        BackgroundWork? search = null;
        using var waiting = new ManualResetEventSlim();
        record.WhileWaitingForOperations = waiting.Set;
        Pkcs11Slot slot = Slot;
        Pkcs11Login? login = null;
        BackgroundWork logIn = BackgroundWork.Run(() => login = slot.ShareOrLogin(LoginCredential.FromPinSource(() =>
        {
            // The prompt: an operation starts on another session meanwhile.
            search = BackgroundWork.Run(() => other.FindCertificates().Dispose());
            Assert.True(inSearch.Wait(Timeout));
            return new SecurePin(_module.ExpectedPin);
        })));
        try
        {
            Assert.True(waiting.Wait(Timeout, TestContext.Current.CancellationToken), $"the login did not wait: {logIn.Failure}");
            Assert.Equal(0, _module.LoginCalls);
        }
        finally
        {
            releaseSearch.Set();
        }

        Assert.True(logIn.Join(Timeout));
        Assert.True(search!.Join(Timeout));
        using (login)
        {
            Assert.Null(logIn.Failure);
            Assert.True(login!.IsActive);
            Assert.Equal(1, _module.LoginCalls);
        }
    }

    // InitToken through a slot found by its token label, once another token is in the slot: neither sent the SO PIN nor
    // initialized (which would erase it).
    [Fact]
    public void InitToken_SlotSelectedByLabel_TokenSwapped_NothingSent()
    {
        Pkcs11Slot slot = _library.GetSlotByTokenLabel(LoginTokenModule.TokenLabel);
        _module.Label = "another";

        var ex = Assert.Throws<Pkcs11TokenException>(() => slot.InitTokenWithPin(_pin, "fresh"));
        var pinpad = Assert.Throws<Pkcs11TokenException>(() => slot.InitTokenWithPinpad("fresh"));

        Assert.Equal(CKR.CKR_TOKEN_NOT_RECOGNIZED, ex.ReturnValue);
        Assert.Equal(CKR.CKR_TOKEN_NOT_RECOGNIZED, pinpad.ReturnValue);
        Assert.Equal(0, _module.InitTokenCalls);
        Assert.Equal("another", _module.Label);
    }

    // On a token that never gives a handle out twice and refuses one it never gave (StrictHandles), a private key found
    // before a logout is refused by the library after it, before the module; the key opened again under a new login
    // signs.
    [Fact]
    public void PrivateKey_AfterRelogin_OldHandleRefusedBeforeTheModule_NewOneSigns()
    {
        _module.StrictHandles = true;
        _module.AddObject(CKO.CKO_PRIVATE_KEY, "k", isPrivate: true, keyType: CKK.CKK_EC);
        var ecdsa = new Mechanism(CKM.CKM_ECDSA_SHA256);
        using Pkcs11Session session = Slot.OpenSession(SessionAccess.ReadOnly);
        Pkcs11Key old;
        using (Pkcs11Login first = Slot.Login(TokenUser.User, _pin))
        {
            old = session.OpenKey("k");
            Assert.NotEmpty(old.Sign(ecdsa, "data"u8));
        }

        using Pkcs11Login second = Slot.Login(TokenUser.User, _pin);
        _module.ClearCallLog();
        using (old)
            Assert.Throws<Pkcs11LoginEndedException>(() => old.Sign(ecdsa, "data"u8));
        Assert.DoesNotContain("C_SignInit", _module.CallLog);
        using Pkcs11Key again = session.OpenKey("k");
        Assert.NotEmpty(again.Sign(ecdsa, "data"u8));
    }

    // ShareOrLogin through a slot found by its token, once another token is in the slot: refused before the PIN source
    // runs, so nobody is prompted for a PIN that would not be sent.
    [Fact]
    public void ShareOrLogin_TokenSwapped_PinSourceNotCalled()
    {
        Pkcs11Slot slot = _library.GetSlotByTokenLabel(LoginTokenModule.TokenLabel);
        _module.Label = "another";
        bool asked = false;

        var ex = Assert.Throws<Pkcs11TokenException>(() => slot.ShareOrLogin(LoginCredential.FromPinSource(() =>
        {
            asked = true;
            return new SecurePin(_module.ExpectedPin);
        })));

        Assert.Equal(CKR.CKR_TOKEN_NOT_RECOGNIZED, ex.ReturnValue);
        Assert.False(asked);
        Assert.Equal(0, _module.LoginCalls);
    }
}
