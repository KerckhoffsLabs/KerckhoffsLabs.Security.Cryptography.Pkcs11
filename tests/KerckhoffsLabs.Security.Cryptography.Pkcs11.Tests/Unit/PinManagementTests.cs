using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// PIN management where PKCS#11 v3.2 allows it (slot_and_token_mgmt_functions.md): <c>C_InitPIN</c> only in the
/// "R/W SO Functions" state, so it belongs to a Security Officer login and runs on that login's anchor;
/// <c>C_SetPIN</c> only in a read/write session, so a read-only one refuses it before the module.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class PinManagementTests : IDisposable
{
    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;
    private readonly SecurePin _newPin = new("5678"u8);

    public PinManagementTests()
    {
        _library = _module.Load();
        _pin = new SecurePin(_module.ExpectedPin);
    }

    public void Dispose()
    {
        _newPin.Dispose();
        _pin.Dispose();
        _library.Dispose();
        _module.Dispose();
    }

    private Pkcs11Slot Slot => Assert.Single(_library.GetSlotList());

    // ---- C_InitPIN ----

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InitUserPin_OnUserLogin_RefusedBeforeModule(bool pinpad)
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);

        var ex = Assert.Throws<InvalidOperationException>(() =>
        {
            if (pinpad)
                login.InitUserPinWithPinpad();
            else
                login.InitUserPinWithPin(_newPin);
        });

        Assert.Contains("Security Officer", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, _module.CallCount("C_InitPIN"));
        Assert.True(login.IsActive);
    }

    [Fact]
    public void InitUserPin_OnSoLogin_SendsInitPinOnAnchor()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.SecurityOfficer, _pin);
        (ulong anchor, bool anchorReadWrite) = Assert.Single(_module.OpenSessions);

        login.InitUserPinWithPin(_newPin);

        Assert.True(anchorReadWrite);
        (ulong session, byte[] pin) = Assert.NotNull(_module.LastInitPin);
        Assert.Equal(anchor, session);
        Assert.Equal("5678"u8.ToArray(), pin);
        Assert.Single(_module.OpenSessions); // no session of its own
        Assert.True(login.IsActive);
    }

    [Fact]
    public void InitUserPinWithPinpad_OnSoLogin_SendsNoPinOnAnchor()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.SecurityOfficer, _pin);
        (ulong anchor, _) = Assert.Single(_module.OpenSessions);

        login.InitUserPinWithPinpad();

        (ulong session, byte[] pin) = Assert.NotNull(_module.LastInitPin);
        Assert.Equal(anchor, session);
        Assert.Empty(pin);
    }

    [Fact]
    public void InitUserPin_NullPin_Throws()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.SecurityOfficer, _pin);

        Assert.Throws<ArgumentNullException>(() => login.InitUserPinWithPin(null!));
        Assert.Equal(0, _module.CallCount("C_InitPIN"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InitUserPin_AfterTheLoginIsDisposed_ThrowsObjectDisposed(bool pinpad)
    {
        using Pkcs11Login login = Slot.Login(TokenUser.SecurityOfficer, _pin);
        login.Dispose();

        var ex = Assert.Throws<ObjectDisposedException>(() =>
        {
            if (pinpad)
                login.InitUserPinWithPinpad();
            else
                login.InitUserPinWithPin(_newPin);
        });

        Assert.Contains("login", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, _module.CallCount("C_InitPIN"));
    }

    [Fact]
    public void InitUserPin_WhileASessionStillHoldsTheLogin_RunsOnTheAnchor()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.SecurityOfficer, _pin);
        using Pkcs11Session session = login.OpenSession();
        using Pkcs11Login second = login.Share();
        login.Dispose();

        second.InitUserPinWithPin(_newPin);

        Assert.Equal(_module.OpenSessions[0].Handle, Assert.NotNull(_module.LastInitPin).Session);
    }

    [Fact]
    public void InitUserPin_AnchorLost_EndsTheLogin()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.SecurityOfficer, _pin);
        _module.FailSession(_module.OpenSessions[0].Handle, CKR.CKR_DEVICE_REMOVED);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => login.InitUserPinWithPin(_newPin));

        Assert.Equal(CKR.CKR_DEVICE_REMOVED, ex.ReturnValue);
        Assert.False(login.IsActive);
        Assert.Throws<ObjectDisposedException>(() => login.InitUserPinWithPin(_newPin));
    }

    [Fact]
    public async Task InitUserPin_WhileASecondLoginProbesTheAnchor_WaitsItsTurn()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using Pkcs11Login login = Slot.Login(TokenUser.SecurityOfficer, _pin);
        using var inLogin = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        _module.DuringGetSessionInfo = _ =>
        {
            inLogin.Set();
            release.Wait(TimeSpan.FromSeconds(10), ct);
        };

        Task<Pkcs11Login> share = Task.Run(() => Slot.Login(TokenUser.SecurityOfficer, _pin), ct);
        try
        {
            Assert.True(inLogin.Wait(TimeSpan.FromSeconds(10), ct));
            Task init = Task.Run(() => login.InitUserPinWithPin(_newPin), ct);

            // Not refused as concurrent use of the anchor: it waits for the probe sent on it.
            Task first = await Task.WhenAny(init, Task.Delay(TimeSpan.FromMilliseconds(200), ct));
            Assert.NotSame(init, first);
            release.Set();
            await init.WaitAsync(TimeSpan.FromSeconds(10), ct);
        }
        finally
        {
            release.Set();
            await Assert.ThrowsAsync<Pkcs11AuthenticationException>(() => share);
        }
        Assert.NotNull(_module.LastInitPin);
    }

    [Fact]
    public void Session_HasNoInitPin()
    {
        Assert.Null(typeof(Pkcs11Session).GetMethod("InitPinWithPin"));
        Assert.Null(typeof(Pkcs11Session).GetMethod("InitPinWithPinpad"));
    }

    // ---- C_SetPIN ----

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void SetPin_OnReadOnlySession_RefusedWithSessionReadOnly(bool loggedIn, bool pinpad)
    {
        using Pkcs11Login? login = loggedIn ? Slot.Login(TokenUser.User, _pin) : null;
        using Pkcs11Session session = login is null
            ? Slot.OpenSession(SessionAccess.ReadOnly)
            : login.OpenSession(SessionAccess.ReadOnly);

        var ex = Assert.Throws<Pkcs11SessionException>(() =>
        {
            if (pinpad)
                session.SetPinWithPinpad();
            else
                session.SetPinWithPin(_pin, _newPin);
        });

        Assert.Equal(CKR.CKR_SESSION_READ_ONLY, ex.ReturnValue);
        Assert.Contains("read-only", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, _module.CallCount("C_SetPIN"));
    }

    [Fact]
    public void SetPin_OnReadWritePublicSession_Sent()
    {
        using Pkcs11Session session = Slot.OpenSession(SessionAccess.ReadWrite);

        session.SetPinWithPin(_pin, _newPin);

        (ulong sent, byte[] oldPin, byte[] newPin) = Assert.NotNull(_module.LastSetPin);
        Assert.Equal(Assert.Single(_module.OpenSessions).Handle, sent);
        Assert.Equal(_module.ExpectedPin, oldPin);
        Assert.Equal("5678"u8.ToArray(), newPin);
    }

    [Fact]
    public void SetPinWithPinpad_OnReadWriteUserSession_SendsNoPins()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();

        session.SetPinWithPinpad();

        (ulong sent, byte[] oldPin, byte[] newPin) = Assert.NotNull(_module.LastSetPin);
        Assert.Equal(_module.OpenSessions[1].Handle, sent); // [0] is the login's anchor
        Assert.Empty(oldPin);
        Assert.Empty(newPin);
    }
}
