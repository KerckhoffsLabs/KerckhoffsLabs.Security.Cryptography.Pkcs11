using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// What PKCS#11 v3.2 forbids and the library knows from state it owns across every load of the module (its
/// sessions, by access, and its logins), refused before the module with the code the module would answer:
/// an SO login while a read-only session is open (<c>CKR_SESSION_READ_ONLY_EXISTS</c>), a read-only session
/// while the SO is logged in (<c>CKR_SESSION_READ_WRITE_SO_EXISTS</c>), and <c>C_InitToken</c> while the
/// application has a session or login on the token (<c>CKR_SESSION_EXISTS</c>).
/// </summary>
/// <remarks>
/// Each case runs through the library that holds the state and through a second load of the same module, which
/// shares it.
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class LoginRefusalTests : IDisposable
{
    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public LoginRefusalTests()
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

    // A second load of the module for the refused call to go through, or null to go through this one; the caller
    // holds it in a using declaration.
    private Pkcs11Library? SecondLoad(bool secondLoad) => secondLoad ? _module.Load() : null;

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SoLogin_WhileLibraryHasReadOnlySession_RefusedBeforeModule(bool secondLoad)
    {
        using Pkcs11Session readOnly = SlotOf(_library).OpenSession(SessionAccess.ReadOnly);
        using Pkcs11Library? second = SecondLoad(secondLoad);
        Pkcs11Slot slot = SlotOf(second ?? _library);

        var ex = Assert.Throws<Pkcs11SessionException>(() => slot.Login(TokenUser.SecurityOfficer, _pin));

        Assert.Equal(CKR.CKR_SESSION_READ_ONLY_EXISTS, ex.ReturnValue);
        Assert.Contains("read-only", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, _module.LoginCalls);
        Assert.Single(_module.OpenSessions); // no anchor left behind
        Assert.Null(_module.LoggedIn);
    }

    [Fact]
    public void SoLogin_WithOnlyReadWriteSessions_ReachesTheModule()
    {
        using Pkcs11Session readWrite = SlotOf(_library).OpenSession(SessionAccess.ReadWrite);

        using Pkcs11Login login = SlotOf(_library).Login(TokenUser.SecurityOfficer, _pin);

        Assert.Equal(1, _module.LoginCalls);
        Assert.Equal(CKU.CKU_SO, _module.LoggedIn);
    }

    [Fact]
    public void SoLogin_AfterTheReadOnlySessionCloses_ReachesTheModule()
    {
        SlotOf(_library).OpenSession(SessionAccess.ReadOnly).Dispose();

        using Pkcs11Login login = SlotOf(_library).Login(TokenUser.SecurityOfficer, _pin);

        Assert.Equal(CKU.CKU_SO, _module.LoggedIn);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReadOnlySession_WhileSoLoggedIn_RefusedBeforeModule(bool secondLoad)
    {
        using Pkcs11Login so = SlotOf(_library).Login(TokenUser.SecurityOfficer, _pin);
        using Pkcs11Library? second = SecondLoad(secondLoad);
        Pkcs11Slot slot = SlotOf(second ?? _library);
        int opened = _module.CallCount("C_OpenSession");

        var ex = Assert.Throws<Pkcs11SessionException>(() => slot.OpenSession(SessionAccess.ReadOnly));

        Assert.Equal(CKR.CKR_SESSION_READ_WRITE_SO_EXISTS, ex.ReturnValue);
        Assert.Contains("Security Officer", ex.Message, StringComparison.Ordinal);
        Assert.Equal(opened, _module.CallCount("C_OpenSession"));
    }

    [Fact]
    public void ReadOnlySessionFromTheSoLogin_RefusedBeforeModule()
    {
        using Pkcs11Login so = SlotOf(_library).Login(TokenUser.SecurityOfficer, _pin);
        int opened = _module.CallCount("C_OpenSession");

        var ex = Assert.Throws<Pkcs11SessionException>(() => so.OpenSession(SessionAccess.ReadOnly));

        Assert.Equal(CKR.CKR_SESSION_READ_WRITE_SO_EXISTS, ex.ReturnValue);
        Assert.Equal(opened, _module.CallCount("C_OpenSession"));
        Assert.True(so.IsActive);
    }

    [Fact]
    public void ReadOnlySession_WhileUserLoggedIn_ReachesTheModule()
    {
        using Pkcs11Login user = SlotOf(_library).Login(TokenUser.User, _pin);

        using Pkcs11Session session = SlotOf(_library).OpenSession(SessionAccess.ReadOnly);

        Assert.Equal(CKS.CKS_RO_USER_FUNCTIONS, session.GetSessionInfo().State);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void InitToken_WhileLibraryHasSessionOrLogin_RefusedBeforeModule(bool secondLoad, bool login)
    {
        // A login holds a session of its own (its anchor), which is what the token counts.
        using IDisposable holder = login
            ? SlotOf(_library).Login(TokenUser.User, _pin)
            : SlotOf(_library).OpenSession();
        using Pkcs11Library? second = SecondLoad(secondLoad);
        Pkcs11Slot slot = SlotOf(second ?? _library);

        var ex = Assert.Throws<Pkcs11SessionException>(() => slot.InitTokenWithPin(_pin, "fresh"));
        Assert.Equal(CKR.CKR_SESSION_EXISTS, ex.ReturnValue);
        Assert.Contains("session", ex.Message, StringComparison.Ordinal);

        var pinpad = Assert.Throws<Pkcs11SessionException>(() => slot.InitTokenWithPinpad("fresh"));
        Assert.Equal(CKR.CKR_SESSION_EXISTS, pinpad.ReturnValue);

        Assert.Equal(0, _module.InitTokenCalls);
    }

    [Fact]
    public void InitToken_WithNoSessionOrLogin_ReachesTheModule()
    {
        SlotOf(_library).OpenSession().Dispose();
        using (SlotOf(_library).Login(TokenUser.User, _pin)) { }

        SlotOf(_library).InitTokenWithPin(_pin, "fresh");

        Assert.Equal(1, _module.InitTokenCalls);
    }
}
