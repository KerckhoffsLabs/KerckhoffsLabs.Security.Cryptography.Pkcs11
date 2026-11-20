using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The edges of a token login's life: its session lost between <c>C_Login</c> and the check that follows it; a context
/// login answered <c>CKR_OPERATION_NOT_INITIALIZED</c> once the login is gone (OpenSC); the module finalized under it by
/// another component (<c>CKR_CRYPTOKI_NOT_INITIALIZED</c>); and the API around it: <see cref="TokenUser"/> values,
/// slot equality, a <c>ShareOrLogin</c> PIN the caller keeps, and concurrent disposal.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class TokenLoginEdgeTests : IDisposable
{
    private const string AlwaysAuthenticateEc = "aa-ec";
    private static readonly Mechanism Ecdsa = new(CKM.CKM_ECDSA_SHA256);

    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public TokenLoginEdgeTests()
    {
        _module.AddObject(CKO.CKO_PRIVATE_KEY, AlwaysAuthenticateEc, isPrivate: true, keyType: CKK.CKK_EC,
            more: new Dictionary<CKA, byte[]> { [CKA.CKA_ALWAYS_AUTHENTICATE] = [1] });
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

    // The login's session lost right after the module accepted the login (a network HSM failing over): the login is not
    // recorded with a dead session, which would refuse every later login of the user as one already made; it fails, is
    // logged out on a session opened for that, and the next login goes ahead.
    [Fact]
    public void AnchorLostRightAfterTheLogin_LoginFails_NextLoginSucceeds()
    {
        using Pkcs11Session other = Slot.OpenSession(SessionAccess.ReadOnly);
        _module.DuringLogin = _ =>
        {
            _module.DuringLogin = null;
            _module.FailNext("C_GetSessionInfo", CKR.CKR_SESSION_HANDLE_INVALID);
        };

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => Slot.Login(TokenUser.User, _pin));

        Assert.Equal(CKR.CKR_SESSION_HANDLE_INVALID, ex.ReturnValue);
        Assert.False(Slot.LoginRecord.IsLoggedIn);
        Assert.False(Slot.LoginRecord.MayStillBeLoggedIn);
        Assert.Null(_module.LoggedIn);
        using Pkcs11Login next = Slot.Login(TokenUser.User, _pin);
        Assert.True(next.IsActive);
    }

    // OpenSC answers a context login CKR_OPERATION_NOT_INITIALIZED once the card's login is gone, not only when the key
    // needs none: the session's state, public, tells which. The login ends, and the operation fails without signing.
    [Fact]
    public void ContextLogin_OperationNotInitialized_SessionPublic_EndsTheLogin()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = ContextAuthentication.FromPinSource(_ => new SecurePin(_module.ExpectedPin));
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.DuringLogin = _ =>
        {
            // The context login: the card was reset by another process meanwhile.
            _module.DuringLogin = null;
            _module.DropLogin();
            _module.FailNext("C_Login", CKR.CKR_OPERATION_NOT_INITIALIZED);
        };
        _module.ClearCallLog();

        var ex = Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Equal(CKR.CKR_USER_NOT_LOGGED_IN, ex.ReturnValue);
        Assert.False(login.IsActive);
        Assert.DoesNotContain("C_Sign", _module.CallLog);
    }

    // The module finalized under the login by another component of the process (C_Finalize closes every session): the
    // login's session answers CKR_CRYPTOKI_NOT_INITIALIZED, which is taken as the login gone, not as a login held.
    [Fact]
    public void CryptokiNotInitialized_OnTheLoginsSession_EndsTheLogin_NextLoginSucceeds()
    {
        Pkcs11Login first = Slot.Login(TokenUser.User, _pin);
        ulong anchor = Assert.Single(_module.OpenSessions).Handle;
        _module.DropLogin();
        _module.FailNext("C_GetSessionInfo", CKR.CKR_CRYPTOKI_NOT_INITIALIZED);
        _module.ClearCallLog();

        using Pkcs11Login second = Slot.Login(TokenUser.User, _pin);

        // No C_CloseSession with the lost anchor's number: the module closed every session, and once initialized
        // again may give the number to a session of whoever initialized it.
        Assert.DoesNotContain("C_CloseSession", _module.CallLog);
        Assert.Contains(_module.OpenSessions, open => open.Handle == anchor); // left to the module
        Assert.False(first.IsActive);
        Assert.True(second.IsActive);
        Assert.False(Slot.LoginRecord.MayStillBeLoggedIn);
        Assert.Equal(2, _module.LoginCalls);
        first.Dispose();
    }

    // TokenUser is not a CKU: a cast from one picks the same user or none, never the other, and none is refused.
    [Fact]
    public void TokenUser_CastFromCku_IsTheSameUserOrRefused()
    {
        Assert.Equal(TokenUser.User, (TokenUser)(ulong)CKU.CKU_USER);
        Assert.False(Enum.IsDefined((TokenUser)(ulong)CKU.CKU_SO));
        Assert.False(Enum.IsDefined((TokenUser)(ulong)CKU.CKU_CONTEXT_SPECIFIC));
        Assert.False(Enum.IsDefined(default(TokenUser)));

        Assert.Throws<ArgumentOutOfRangeException>(() => Slot.Login((TokenUser)(ulong)CKU.CKU_SO, _pin));
        Assert.Throws<ArgumentOutOfRangeException>(() => Slot.Login(default, _pin));
        Assert.Equal(0, _module.LoginCalls);
    }

    // A slot looked up by its token checks it still holds that token before a login; a listed one does not. They are
    // not equal, so a set of slots never trades one for the other; two lookups of the same token are.
    [Fact]
    public void Slot_FromALookup_NotEqualToTheListedOne()
    {
        Pkcs11Slot listed = Slot;
        Pkcs11Slot found = _library.GetSlotByTokenLabel(LoginTokenModule.TokenLabel);
        Pkcs11Slot foundAgain = _library.GetSlotByTokenLabel(LoginTokenModule.TokenLabel);

        Assert.NotEqual(listed, found);
        Assert.Equal(found, foundAgain);
        Assert.Equal(found.GetHashCode(), foundAgain.GetHashCode());
        Assert.Equal(listed, Slot);
        Assert.Equal(2, new HashSet<Pkcs11Slot> { listed, found, foundAgain }.Count);
    }

    // ShareOrLogin with a PIN at hand: the caller keeps it, as with Login, so it is still usable after.
    [Fact]
    public void ShareOrLogin_APinTheCallerKeeps_NotDisposed()
    {
        using (Pkcs11Login first = Slot.ShareOrLogin(_pin))
        using (Pkcs11Login shared = Slot.ShareOrLogin(_pin))
        {
            Assert.True(shared.IsActive);
            Assert.Equal(1, _module.LoginCalls);
        }

        Assert.False(_pin.IsDisposed);
        using Pkcs11Login again = Slot.Login(TokenUser.User, _pin);
        Assert.True(again.IsActive);
    }

    // A slot found by its token shares the login held only while it holds that token: one swapped in since (here,
    // relabelled) is refused, and nothing is sent.
    [Fact]
    public void ShareOrLogin_ThroughALookup_TokenSwapped_Refused()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Pkcs11Slot found = _library.GetSlotByTokenLabel(LoginTokenModule.TokenLabel);
        _module.Label = "another-token";
        int loginCalls = _module.LoginCalls;

        var ex = Assert.Throws<Pkcs11TokenException>(() => found.ShareOrLogin(_pin));

        Assert.Equal(CKR.CKR_TOKEN_NOT_RECOGNIZED, ex.ReturnValue);
        Assert.Equal(loginCalls, _module.LoginCalls);
        Assert.True(login.IsActive);
    }

    // A PIN the caller keeps, disposed on another thread while the library sends it: the module gets the PIN, not a
    // buffer zeroed half way, and the PIN is zeroed once the send ends.
    [Fact]
    public void CallerPin_DisposedDuringTheSend_SentWhole_ZeroedAfter()
    {
        var pin = new SecurePin(_module.ExpectedPin);
        _module.DuringLogin = _ =>
        {
            _module.DuringLogin = null;
            var disposing = new Thread(pin.Dispose);
            disposing.Start();
            Assert.True(disposing.Join(TimeSpan.FromSeconds(30)));
        };

        using Pkcs11Login login = Slot.Login(TokenUser.User, pin);

        Assert.True(login.IsActive);
        Assert.True(pin.IsDisposed);
        Assert.Throws<ObjectDisposedException>(() => pin.Length);
    }

    // A use of a PIN holds off its zeroing: disposed meanwhile, it stays readable for the use, and is zeroed as the last
    // use ends.
    [Fact]
    public void SecurePin_DisposedDuringAUse_ZeroedWhenTheUseEnds()
    {
        var pin = new SecurePin("1234");
        SecurePin.Use use = pin.BeginUse();
        pin.Dispose();

        Assert.True(pin.IsDisposed);
        Assert.Equal("1234"u8.ToArray(), pin.Pin.ToArray());
        Assert.Throws<ObjectDisposedException>(() => pin.BeginUse());

        use.Dispose();

        Assert.Throws<ObjectDisposedException>(() => pin.Pin.Length);
    }

    // A login left on the token, carried from a registry dropped with the module still initialized to the next one: taken
    // back for the slot only while the module was not finalized through the library meanwhile, and only once.
    [Fact]
    public void LeftBehind_CarriedToTheNextRegistry_OnlyIfNotFinalizedMeanwhile()
    {
        var carried = new TokenLoginRegistry.LeftBehindBySlot();
        carried.Put(1, TokenUser.User, finalizations: 4);
        carried.Put(2, TokenUser.SecurityOfficer, finalizations: 4);

        Assert.Equal(TokenUser.User, carried.Take(1, finalizations: 4));
        Assert.Null(carried.Take(1, finalizations: 4)); // once
        Assert.Null(carried.Take(2, finalizations: 5)); // finalized since: the login ended with it
        Assert.Null(carried.Take(3, finalizations: 4));
    }

    // Two threads dispose the library at once: one disposal runs, the other returns, neither throws.
    [Fact]
    public void Library_DisposedFromTwoThreadsAtOnce_NeitherThrows()
    {
        for (int round = 0; round < 20; round++)
        {
            // Another load of the module, beside the one the class keeps.
            Pkcs11Library library = _module.Load();
            using Pkcs11Login login = Assert.Single(library.GetSlotList()).Login(TokenUser.User, _pin);
            using var start = new Barrier(2);
            Exception? failure = null;
            void DisposeIt()
            {
                start.SignalAndWait();
                try
                {
                    library.Dispose();
                }
                catch (Exception ex)
                {
                    failure = ex;
                }
            }
            var other = new Thread(DisposeIt);
            other.Start();
            DisposeIt();
            Assert.True(other.Join(TimeSpan.FromSeconds(30)));
            Assert.Null(failure);
            Assert.False(login.IsActive);
        }
    }
}
