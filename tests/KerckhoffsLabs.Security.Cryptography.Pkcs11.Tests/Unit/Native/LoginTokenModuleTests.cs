using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Pins <see cref="LoginTokenModule"/> to the PKCS#11 v3.2 login rules it models
/// (session_mgmt_functions.md: C_OpenSession, C_CloseSession, C_Login, C_Logout), so the tests built on
/// it test the library against the spec rather than against the fake's own ideas. Driven through the
/// low-level wrappers, with no library logic in between.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class LoginTokenModuleTests : IDisposable
{
    private static readonly NativeCULong Slot = (NativeCULong)LoginTokenModule.SlotId;

    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;

    public LoginTokenModuleTests() => _library = _module.Load();

    private LowLevelPkcs11Library LowLevel => _library.LowLevelLibrary!;

    public void Dispose()
    {
        _library.Dispose();
        _module.Dispose();
    }

    private NativeCULong Open(bool readWrite)
    {
        ulong flags = CKF.CKF_SERIAL_SESSION | (readWrite ? CKF.CKF_RW_SESSION : 0);
        Assert.Equal(CKR.CKR_OK, LowLevel.C_OpenSession(Slot, (NativeCULong)flags, out NativeCULong session));
        return session;
    }

    private CKR Login(NativeCULong session, CKU user) => LowLevel.C_Login(session, user, _module.ExpectedPin);

    [Fact]
    public void SecondLogin_SameUser_IsAlreadyLoggedIn()
    {
        NativeCULong first = Open(readWrite: false);
        NativeCULong second = Open(readWrite: false);
        Assert.Equal(CKR.CKR_OK, Login(first, CKU.CKU_USER));

        Assert.Equal(CKR.CKR_USER_ALREADY_LOGGED_IN, Login(second, CKU.CKU_USER));
        Assert.Equal(2, _module.LoginCalls);
    }

    [Fact]
    public void Login_OtherUser_IsAnotherAlreadyLoggedIn()
    {
        NativeCULong session = Open(readWrite: true);
        Assert.Equal(CKR.CKR_OK, Login(session, CKU.CKU_USER));

        Assert.Equal(CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN, Login(session, CKU.CKU_SO));
        Assert.Equal(CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
            LowLevel.C_LoginUser(session, CKU.CKU_USER, _module.ExpectedPin, "alice"u8));
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
    }

    [Fact]
    public void SoLogin_WithReadOnlySession_IsReadOnlyExists()
    {
        NativeCULong readWrite = Open(readWrite: true);
        _ = Open(readWrite: false);

        Assert.Equal(CKR.CKR_SESSION_READ_ONLY_EXISTS, Login(readWrite, CKU.CKU_SO));
        Assert.Null(_module.LoggedIn);
    }

    [Fact]
    public void OpenReadOnly_WithSoLoggedIn_IsReadWriteSoExists()
    {
        NativeCULong readWrite = Open(readWrite: true);
        Assert.Equal(CKR.CKR_OK, Login(readWrite, CKU.CKU_SO));

        CKR rv = LowLevel.C_OpenSession(Slot, (NativeCULong)CKF.CKF_SERIAL_SESSION, out _);

        Assert.Equal(CKR.CKR_SESSION_READ_WRITE_SO_EXISTS, rv);
        Assert.Single(_module.OpenSessions);
    }

    [Fact]
    public void OpenReadWrite_OnWriteProtectedToken_IsTokenWriteProtected()
    {
        _module.WriteProtected = true;

        CKR rv = LowLevel.C_OpenSession(Slot, (NativeCULong)(CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), out _);

        Assert.Equal(CKR.CKR_TOKEN_WRITE_PROTECTED, rv);
        _ = Open(readWrite: false);
    }

    [Fact]
    public void ClosingLastSession_LogsOut()
    {
        NativeCULong first = Open(readWrite: false);
        NativeCULong second = Open(readWrite: false);
        Assert.Equal(CKR.CKR_OK, Login(first, CKU.CKU_USER));

        Assert.Equal(CKR.CKR_OK, LowLevel.C_CloseSession(first));
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);

        Assert.Equal(CKR.CKR_OK, LowLevel.C_CloseSession(second));
        Assert.Null(_module.LoggedIn);
        Assert.Equal(0, _module.LogoutCalls);
    }

    [Fact]
    public void Logout_WhenNotLoggedIn_IsUserNotLoggedIn()
    {
        NativeCULong session = Open(readWrite: false);

        Assert.Equal(CKR.CKR_USER_NOT_LOGGED_IN, LowLevel.C_Logout(session));
        Assert.Equal(1, _module.LogoutCalls);
    }

    [Fact]
    public void WrongPin_IsPinIncorrect_AndLeavesSessionsPublic()
    {
        NativeCULong session = Open(readWrite: false);

        Assert.Equal(CKR.CKR_PIN_INCORRECT, LowLevel.C_Login(session, CKU.CKU_USER, "0000"u8));
        Assert.Null(_module.LoggedIn);
    }

    [Fact]
    public void SessionState_FollowsLogin()
    {
        NativeCULong readOnly = Open(readWrite: false);
        NativeCULong readWrite = Open(readWrite: true);
        Assert.Equal(CKS.CKS_RO_PUBLIC_SESSION, State(readOnly));
        Assert.Equal(CKS.CKS_RW_PUBLIC_SESSION, State(readWrite));

        // Logged in through the other session: the login is the application's, not the session's.
        Assert.Equal(CKR.CKR_OK, Login(readWrite, CKU.CKU_USER));
        Assert.Equal(CKS.CKS_RO_USER_FUNCTIONS, State(readOnly));
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, State(readWrite));

        Assert.Equal(CKR.CKR_OK, LowLevel.C_Logout(readOnly));
        Assert.Equal(CKS.CKS_RO_PUBLIC_SESSION, State(readOnly));

        Assert.Equal(CKR.CKR_OK, LowLevel.C_CloseSession(readOnly));
        Assert.Equal(CKR.CKR_OK, Login(readWrite, CKU.CKU_SO));
        Assert.Equal(CKS.CKS_RW_SO_FUNCTIONS, State(readWrite));
    }

    private CKS State(NativeCULong session)
    {
        Assert.Equal(CKR.CKR_OK, LowLevel.C_GetSessionInfo(session, out CK_SESSION_INFO info));
        return (CKS)(ulong)info.State;
    }
}
