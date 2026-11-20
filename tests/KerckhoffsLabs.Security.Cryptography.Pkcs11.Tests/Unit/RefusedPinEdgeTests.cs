using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The edges of the refused-PIN memory (<see cref="RefusedPins"/>): a PIN changed outside the library while a login made
/// with it is held, the user's PIN remembered for that login (replaced by <c>C_SetPIN</c>, forgotten when the login
/// ends), what a PIN set on the pinpad or a token initialized forgets, the old PIN of <c>C_SetPIN</c> checked against the
/// context refusals, a <c>C_SetPIN</c> that another login overlaps, the lifetime a refusal was recorded with, the
/// capacity, and what makes a key's scope.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class RefusedPinEdgeTests : IDisposable
{
    private const string First = "aa-1";
    private const string Second = "aa-2";
    private const string Third = "aa-3";
    private const string Qualified = "qes";
    private static readonly Mechanism Ecdsa = new(CKM.CKM_ECDSA_SHA256);
    private static readonly byte[] SignaturePin = "778899"u8.ToArray();

    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public RefusedPinEdgeTests()
    {
        foreach (string label in new[] { First, Second, Third, Qualified })
        {
            _module.AddObject(CKO.CKO_PRIVATE_KEY, label, isPrivate: true, keyType: CKK.CKK_EC,
                more: new Dictionary<CKA, byte[]> { [CKA.CKA_ALWAYS_AUTHENTICATE] = [1] });
        }
        _module.KeyPins[Qualified] = SignaturePin;
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

    private static ContextAuthentication Pin(byte[] pin) => ContextAuthentication.FromPinSource(_ => new SecurePin(pin));

    // ---- A PIN changed outside the library while a login made with it is held ----

    // The first key that refuses the login's PIN may have a PIN of its own: that refusal is the key's. A second key
    // refusing it too is taken for the PIN changed since: refused for every key and the next login. Two retries in all,
    // not one per key plus one for the next login.
    [Fact]
    public void PinChangedWhileLoginHeld_SecondKeyRefusal_TakenForStale_TwoRetriesInAll()
    {
        byte[] loginPin = _module.ExpectedPin;
        using (Pkcs11Login login = Slot.Login(TokenUser.User, _pin))
        using (Pkcs11Session session = login.OpenSession())
        {
            _module.ExpectedPin = "13572468"u8.ToArray(); // an administrator changes it; the secret store is not updated
            session.ContextAuthentication = Pin(loginPin);
            using Pkcs11Key first = session.OpenKey(First);
            using Pkcs11Key second = session.OpenKey(Second);
            using Pkcs11Key third = session.OpenKey(Third);

            Assert.Throws<Pkcs11AuthenticationException>(() => first.Sign(Ecdsa, "data"u8));
            Assert.Throws<Pkcs11AuthenticationException>(() => second.Sign(Ecdsa, "data"u8));
            _module.ClearCallLog();

            var refused = Assert.Throws<Pkcs11AuthenticationException>(() => third.Sign(Ecdsa, "data"u8));

            Assert.Contains("refused this PIN before", refused.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(LoginTokenModule.ContextLogin, _module.CallLog);
        }
        int loginCalls = _module.LoginCalls;

        var next = Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, _pin));

        Assert.Contains("refused this PIN before", next.Message, StringComparison.Ordinal);
        Assert.Equal(loginCalls, _module.LoginCalls);
        Assert.Equal(2, _module.WrongPins(CKU.CKU_USER));
    }

    // One key with a PIN of its own refusing the login's PIN is that key's refusal: the others still get it.
    [Fact]
    public void LoginPinRefusedByOneKey_OthersStillGetIt()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = Pin(_module.ExpectedPin);
        using Pkcs11Key qualified = session.OpenKey(Qualified);
        using Pkcs11Key first = session.OpenKey(First);

        Assert.Throws<Pkcs11AuthenticationException>(() => qualified.Sign(Ecdsa, "data"u8));

        Assert.NotEmpty(first.Sign(Ecdsa, "data"u8));
        Assert.Throws<Pkcs11AuthenticationException>(() => qualified.Sign(Ecdsa, "data"u8)); // refused before, still
    }

    // ---- The user's PIN remembered for the login held ----

    // C_SetPIN while the user's login is held: the PIN remembered for it is the new one, so a key with a PIN of its own
    // refusing the new PIN is that key's refusal, and the user's current PIN still reaches the other keys.
    [Fact]
    public void SetPin_WhileLoginHeld_TheNewPinIsTheOneRemembered()
    {
        byte[] newPin = "24681357"u8.ToArray();
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession(SessionAccess.ReadWrite);
        using (var changed = new SecurePin(newPin))
            session.SetPinWithPin(_pin, changed);
        session.ContextAuthentication = Pin(newPin);
        using Pkcs11Key qualified = session.OpenKey(Qualified);
        using Pkcs11Key first = session.OpenKey(First);

        Assert.Throws<Pkcs11AuthenticationException>(() => qualified.Sign(Ecdsa, "data"u8));
        _module.ClearCallLog();

        Assert.NotEmpty(first.Sign(Ecdsa, "data"u8));
        Assert.Contains(LoginTokenModule.ContextLogin, _module.CallLog);
    }

    // The PIN remembered for a login is forgotten when it ends: after a pinpad login, which remembers none, the old
    // login's PIN refused by a key with a PIN of its own is taken for a stale one, not that key's.
    [Fact]
    public void LoginEnds_ItsPinIsForgotten()
    {
        _module.ProtectedAuthenticationPath = true;
        Slot.Login(TokenUser.User, _pin).Dispose();
        using Pkcs11Login pinpad = Slot.LoginWithPinpad(TokenUser.User);
        using Pkcs11Session session = pinpad.OpenSession();
        session.ContextAuthentication = Pin(_module.ExpectedPin);
        using Pkcs11Key qualified = session.OpenKey(Qualified);
        using Pkcs11Key first = session.OpenKey(First);

        Assert.Throws<Pkcs11AuthenticationException>(() => qualified.Sign(Ecdsa, "data"u8));
        _module.ClearCallLog();

        Assert.Throws<Pkcs11AuthenticationException>(() => first.Sign(Ecdsa, "data"u8));
        Assert.DoesNotContain(LoginTokenModule.ContextLogin, _module.CallLog);
    }

    // ---- What a PIN set, or a token initialized, forgets ----

    // The user's PIN set on the pinpad (C_InitPIN, NULL PIN) may be any PIN refused before: the user's refusals and the
    // context ones are forgotten.
    [Fact]
    public void InitPinOnThePinpad_ForgetsTheUsersAndTheContextRefusals()
    {
        _module.ProtectedAuthenticationPath = true;
        using (var stale = new SecurePin("4321"))
            Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, stale));
        using (Pkcs11Login pinpad = Slot.LoginWithPinpad(TokenUser.User))
        using (Pkcs11Session session = pinpad.OpenSession())
        using (Pkcs11Key first = session.OpenKey(First))
        {
            session.ContextAuthentication = Pin("8765"u8.ToArray());
            Assert.Throws<Pkcs11AuthenticationException>(() => first.Sign(Ecdsa, "data"u8)); // a stale context PIN
        }
        using (Pkcs11Login so = Slot.Login(TokenUser.SecurityOfficer, _pin))
            so.InitUserPinWithPinpad();
        int loginCalls = _module.LoginCalls;

        using (var stale = new SecurePin("4321"))
            Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, stale));

        Assert.Equal(loginCalls + 1, _module.LoginCalls); // sent again
        using (Pkcs11Login pinpad = Slot.LoginWithPinpad(TokenUser.User))
        using (Pkcs11Session session = pinpad.OpenSession())
        using (Pkcs11Key first = session.OpenKey(First))
        {
            session.ContextAuthentication = Pin("8765"u8.ToArray());
            _module.ClearCallLog();
            Assert.Throws<Pkcs11AuthenticationException>(() => first.Sign(Ecdsa, "data"u8));
            Assert.Contains(LoginTokenModule.ContextLogin, _module.CallLog); // the context refusal forgotten: sent again
        }
    }

    // A token initialized again, under the same label, is a new token to the refusals: they are all forgotten.
    [Fact]
    public void InitToken_SameLabel_ForgetsEveryRefusal()
    {
        using (var stale = new SecurePin("4321"))
            Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, stale));
        string label = Slot.GetTokenInfo().Label;
        Slot.InitTokenWithPin(_pin, label);
        Assert.Equal(label, Slot.GetTokenInfo().Label);
        int loginCalls = _module.LoginCalls;

        using (var stale = new SecurePin("4321"))
            Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, stale));

        Assert.Equal(loginCalls + 1, _module.LoginCalls);
    }

    // ---- C_SetPIN ----

    // The normal user's PIN is usually the context PIN: one refused as a stale context PIN is not sent as the old PIN
    // of C_SetPIN either, as for a login.
    [Fact]
    public void SetPin_OldPinRefusedAsAContextPin_NotSent()
    {
        _module.ProtectedAuthenticationPath = true;
        using Pkcs11Login pinpad = Slot.LoginWithPinpad(TokenUser.User);
        using Pkcs11Session session = pinpad.OpenSession(SessionAccess.ReadWrite);
        session.ContextAuthentication = Pin("4321"u8.ToArray());
        using (Pkcs11Key first = session.OpenKey(First))
            Assert.Throws<Pkcs11AuthenticationException>(() => first.Sign(Ecdsa, "data"u8));
        int setPins = 0;
        _module.DuringSetPin = () => setPins++;

        using var stale = new SecurePin("4321");
        using var next = new SecurePin("24681357");
        var ex = Assert.Throws<Pkcs11AuthenticationException>(() => session.SetPinWithPin(stale, next));

        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        Assert.Equal(0, setPins);
    }

    // The Security Officer's login ends while C_SetPIN is in flight on a session of the token: whose PIN the call
    // changed is not known once the record no longer shows the SO, so the refusal is filed under no one, and the same
    // old PIN is sent again rather than refused under the wrong user.
    [Fact]
    public void SetPin_LoginChangesMeanwhile_NothingRecorded()
    {
        using Pkcs11Login so = Slot.Login(TokenUser.SecurityOfficer, _pin);
        using Pkcs11Session session = Slot.OpenSession(SessionAccess.ReadWrite);
        int setPins = 0;
        _module.DuringSetPin = () =>
        {
            if (setPins++ == 0)
                Slot.LoginRecord.MarkEnded(CKR.CKR_USER_NOT_LOGGED_IN); // never waits
        };
        using var wrong = new SecurePin("4321");
        using var next = new SecurePin("24681357");

        Assert.Throws<Pkcs11AuthenticationException>(() => session.SetPinWithPin(wrong, next));
        Assert.Throws<Pkcs11AuthenticationException>(() => session.SetPinWithPin(wrong, next));

        Assert.Equal(2, setPins); // sent both times
        // Not filed under the SO either, whose login the first call began under: the SO's login with it reaches the
        // module (which still holds the SO's login it did not report gone, and answers that).
        int loginCalls = _module.LoginCalls;
        var soLogin = Assert.ThrowsAny<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.SecurityOfficer, wrong));
        Assert.DoesNotContain("refused this PIN before", soLogin.Message, StringComparison.Ordinal);
        Assert.Equal(loginCalls + 1, _module.LoginCalls);
    }

    // ---- Named users (C_LoginUser) ----

    // A named user's PIN is the context PIN of its keys too: one refused as a stale context PIN is not sent as the named
    // user's login PIN, nor as the old PIN of its C_SetPIN, as for the unnamed user.
    [Fact]
    public void NamedUser_PinRefusedAsAContextPin_NotSentForTheLoginOrSetPin()
    {
        byte[] loginPin = _module.ExpectedPin;
        using (Pkcs11Login login = Slot.Login(TokenUser.User, "alice", _pin))
        using (Pkcs11Session session = login.OpenSession(SessionAccess.ReadWrite))
        {
            _module.ExpectedPin = "13572468"u8.ToArray(); // changed outside the library
            session.ContextAuthentication = Pin(loginPin);
            using Pkcs11Key first = session.OpenKey(First);
            using Pkcs11Key second = session.OpenKey(Second);
            Assert.Throws<Pkcs11AuthenticationException>(() => first.Sign(Ecdsa, "data"u8));
            Assert.Throws<Pkcs11AuthenticationException>(() => second.Sign(Ecdsa, "data"u8)); // taken for stale
            int setPins = 0;
            _module.DuringSetPin = () => setPins++;
            using var next = new SecurePin("24681357");

            var setPin = Assert.Throws<Pkcs11AuthenticationException>(() => session.SetPinWithPin(_pin, next));

            Assert.Equal(CKR.CKR_PIN_INCORRECT, setPin.ReturnValue);
            Assert.Equal(0, setPins);
        }
        int loginCalls = _module.LoginCalls;

        var again = Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, "alice", _pin));

        Assert.Contains("refused this PIN before", again.Message, StringComparison.Ordinal);
        Assert.Equal(loginCalls, _module.LoginCalls);
        Assert.Equal(2, _module.WrongPins(CKU.CKU_USER));
    }

    // ---- The escalation to a stale PIN ----

    // The second key refusing the login's PIN escalates the refusal to every key, and keeps it for that key too: once the
    // token-wide refusal is forgotten (the PIN set again by the SO, and accepted for the login), the key with a PIN of its
    // own is not sent the user's PIN again.
    [Fact]
    public void Escalated_TheSecondKeysRefusalIsKeptToo()
    {
        _module.KeyPins[Third] = SignaturePin;
        using (Pkcs11Login login = Slot.Login(TokenUser.User, _pin))
        using (Pkcs11Session session = login.OpenSession())
        {
            session.ContextAuthentication = Pin(_module.ExpectedPin);
            using Pkcs11Key qualified = session.OpenKey(Qualified);
            using Pkcs11Key third = session.OpenKey(Third);
            Assert.Throws<Pkcs11AuthenticationException>(() => qualified.Sign(Ecdsa, "data"u8));
            Assert.Throws<Pkcs11AuthenticationException>(() => third.Sign(Ecdsa, "data"u8));
        }
        using (Pkcs11Login so = Slot.Login(TokenUser.SecurityOfficer, _pin))
            so.InitUserPinWithPin(_pin);

        using Pkcs11Login again = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session next = again.OpenSession();
        next.ContextAuthentication = Pin(_module.ExpectedPin);
        using Pkcs11Key firstKey = next.OpenKey(First);
        using Pkcs11Key thirdKey = next.OpenKey(Third);
        Assert.NotEmpty(firstKey.Sign(Ecdsa, "data"u8)); // the token-wide refusal forgotten
        _module.ClearCallLog();

        var refused = Assert.Throws<Pkcs11AuthenticationException>(() => thirdKey.Sign(Ecdsa, "data"u8));

        Assert.Contains("refused this PIN before", refused.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(LoginTokenModule.ContextLogin, _module.CallLog);
    }

    // ---- The user's PIN, forgotten while a context login is in flight ----

    // The login ends (on another thread) while a context login with its PIN is sent: the PIN is forgotten only once that
    // send ends, so a key with a PIN of its own refusing it is that key's refusal, not a stale PIN's for every key.
    [Fact]
    public void LoginEndsDuringAContextLogin_TheRefusalIsTheKeys()
    {
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = Slot.OpenSession(SessionAccess.ReadOnly);
        session.ContextAuthentication = Pin(_module.ExpectedPin);
        using Pkcs11Key qualified = session.OpenKey(Qualified);
        TokenLoginRecord record = Slot.LoginRecord;
        _module.DuringLogin = _ =>
        {
            _module.DuringLogin = null;
            var ending = new Thread(() => record.MarkEnded(CKR.CKR_USER_NOT_LOGGED_IN));
            ending.Start();
            Assert.True(ending.Join(TimeSpan.FromSeconds(30)));
            Assert.True(record.RefusedPins.RemembersUserPin is false); // asked to forget, done once the send ends
        };

        Assert.Throws<Pkcs11AuthenticationException>(() => qualified.Sign(Ecdsa, "data"u8));

        string identity = RefusedPins.TokenIdentity(Slot.GetTokenInfo());
        Assert.False(record.RefusedPins.IsRefused(record.RefusedPins.ContextScope(identity), _module.ExpectedPin));
        Assert.False(record.RefusedPins.RemembersUserPin);
        login.Dispose();
    }

    // ---- C_SetPIN while a first login is being made ----

    // C_SetPIN lands after the module accepted a first login and before the login is recorded: the PIN remembered for
    // the login is still replaced by the new one, so a key with a PIN of its own refusing the new PIN is that key's
    // refusal, and the user's other keys still get it.
    [Fact]
    public void SetPin_DuringAFirstLogin_TheNewPinIsRemembered()
    {
        byte[] newPin = "24681357"u8.ToArray();
        using Pkcs11Session other = Slot.OpenSession(SessionAccess.ReadWrite);
        bool changed = false;
        _module.DuringGetSessionInfo = _ =>
        {
            // The probe that follows the module's answer to the login, before the login is recorded.
            if (changed || _module.LoginCalls == 0 || _module.LoggedIn is null)
                return;
            changed = true;
            using var to = new SecurePin(newPin);
            other.SetPinWithPin(_pin, to);
        };

        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        _module.DuringGetSessionInfo = null;

        Assert.True(changed);
        Assert.True(Slot.LoginRecord.RefusedPins.RemembersUserPin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = Pin(newPin);
        using Pkcs11Key qualified = session.OpenKey(Qualified);
        using Pkcs11Key first = session.OpenKey(First);
        Assert.Throws<Pkcs11AuthenticationException>(() => qualified.Sign(Ecdsa, "data"u8));
        Assert.NotEmpty(first.Sign(Ecdsa, "data"u8));
    }

    // ---- A login that ends ----

    // A login ended by the module (MarkEnded, not a disposal): the PIN remembered for it is forgotten.
    [Fact]
    public void LoginEndedByTheModule_ItsPinIsForgotten()
    {
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Assert.True(Slot.LoginRecord.RefusedPins.RemembersUserPin);

        Slot.LoginRecord.MarkEnded(CKR.CKR_USER_NOT_LOGGED_IN);

        Assert.False(Slot.LoginRecord.RefusedPins.RemembersUserPin);
        login.Dispose();
    }

    // The user's PIN changed on the pinpad: the PIN remembered for the login held is forgotten, no longer the PIN.
    [Fact]
    public void SetPinOnThePinpad_ForgetsThePinRemembered()
    {
        _module.ProtectedAuthenticationPath = true;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession(SessionAccess.ReadWrite);
        Assert.True(Slot.LoginRecord.RefusedPins.RemembersUserPin);

        session.SetPinWithPinpad();

        Assert.False(Slot.LoginRecord.RefusedPins.RemembersUserPin);
    }

    // ---- The lifetime a refusal was recorded with ----

    // Loads of one module share its refusals: each keeps the lifetime of the library that recorded it, whichever load
    // checks it later.
    [Fact]
    public void Lifetime_IsTheRecordingLibrarys()
    {
        LoginTokenModule module = _module;
        using Pkcs11Library shortLived = module.Load(new Pkcs11LibraryOptions { RefusedPinLifetime = TimeSpan.FromMinutes(5) });
        Pkcs11Library forever = _library;
        Pkcs11Slot shortSlot = Assert.Single(shortLived.GetSlotList());
        Pkcs11Slot foreverSlot = Assert.Single(forever.GetSlotList());
        long now = 1_000_000;
        shortSlot.LoginRecord.RefusedPins.Clock = () => now;
        Assert.Same(shortSlot.LoginRecord.RefusedPins, foreverSlot.LoginRecord.RefusedPins);
        using var shortWrong = new SecurePin("1111");
        using var foreverWrong = new SecurePin("2222");

        Assert.Throws<Pkcs11AuthenticationException>(() => shortSlot.Login(TokenUser.User, shortWrong));
        Assert.Throws<Pkcs11AuthenticationException>(() => foreverSlot.Login(TokenUser.User, foreverWrong));
        now += (long)TimeSpan.FromMinutes(5).TotalMilliseconds;
        int loginCalls = module.LoginCalls;

        // Recorded for five minutes, checked by the load without a lifetime: sent again.
        Assert.Throws<Pkcs11AuthenticationException>(() => foreverSlot.Login(TokenUser.User, shortWrong));
        Assert.Equal(loginCalls + 1, module.LoginCalls);
        // Recorded for good, checked by the load with five minutes: still refused.
        var refused = Assert.Throws<Pkcs11AuthenticationException>(() => shortSlot.Login(TokenUser.User, foreverWrong));
        Assert.Contains("refused this PIN before", refused.Message, StringComparison.Ordinal);
        Assert.Equal(loginCalls + 1, module.LoginCalls);
    }

    // ---- The store itself ----

    // Past the capacity the oldest refusal is forgotten: one more retry at worst, and the store does not grow.
    [Fact]
    public void Capacity_OldestForgotten()
    {
        var refused = new RefusedPins();
        string token = "16:0123456789abcdef" + "token";
        byte[] scope = refused.Scope(RefusedPins.Purposes.User, token, []);
        for (int i = 0; i <= RefusedPins.Capacity; i++)
            refused.Refuse(RefusedPins.Purposes.User, token, scope, System.Text.Encoding.ASCII.GetBytes($"pin-{i}"), lifetime: null);

        Assert.Equal(RefusedPins.Capacity, refused.Count);
        Assert.False(refused.IsRefused(scope, "pin-0"u8));
        Assert.True(refused.IsRefused(scope, "pin-1"u8));
        Assert.True(refused.IsRefused(scope, System.Text.Encoding.ASCII.GetBytes($"pin-{RefusedPins.Capacity}")));
    }

    // A key's scope is its class, key type, CKA_ID and CKA_LABEL: keys that differ in any one do not share a refusal.
    [Fact]
    public void KeyScope_TellsKeysApartByTypeIdAndLabel()
    {
        var refused = new RefusedPins();
        string token = "4:0001token";
        byte[] ec = refused.KeyContextScope(token, (ulong)CKO.CKO_PRIVATE_KEY, (ulong)CKK.CKK_EC, [1], "k");

        Assert.Equal(ec, refused.KeyContextScope(token, (ulong)CKO.CKO_PRIVATE_KEY, (ulong)CKK.CKK_EC, [1], "k"));
        Assert.NotEqual(ec, refused.KeyContextScope(token, (ulong)CKO.CKO_PRIVATE_KEY, (ulong)CKK.CKK_RSA, [1], "k"));
        Assert.NotEqual(ec, refused.KeyContextScope(token, (ulong)CKO.CKO_SECRET_KEY, (ulong)CKK.CKK_EC, [1], "k"));
        Assert.NotEqual(ec, refused.KeyContextScope(token, (ulong)CKO.CKO_PRIVATE_KEY, (ulong)CKK.CKK_EC, [2], "k"));
        Assert.NotEqual(ec, refused.KeyContextScope(token, (ulong)CKO.CKO_PRIVATE_KEY, (ulong)CKK.CKK_EC, [1], null));
    }
}
