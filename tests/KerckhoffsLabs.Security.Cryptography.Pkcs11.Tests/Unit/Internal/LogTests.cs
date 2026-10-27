using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

// Verifies the source-generated [LoggerMessage] methods render the exact message text at the right
// level. Pass a CapturingLogger directly (the methods take ILogger), so no global state is touched.
public sealed class LogTests
{
    private static CapturingLogger.Entry Only(CapturingLogger log) => Assert.Single(log.Entries);

    [Fact]
    public void SessionTrace_RendersOperation()
    {
        var log = new CapturingLogger();
        Log.SessionTrace(log, 5, "Sign");
        var e = Only(log);
        Assert.Equal(LogLevel.Debug, e.Level);
        Assert.Equal("Session(5)::Sign", e.Message);
    }

    [Fact]
    public void LibraryTrace_RendersOperation()
    {
        var log = new CapturingLogger();
        Log.LibraryTrace(log, "lib.so", "GetInfo");
        var e = Only(log);
        Assert.Equal(LogLevel.Debug, e.Level);
        Assert.Equal("Pkcs11Library(lib.so)::GetInfo", e.Message);
    }

    [Fact]
    public void SlotTrace_RendersOperation()
    {
        var log = new CapturingLogger();
        Log.SlotTrace(log, 3, "OpenSessionCore");
        var e = Only(log);
        Assert.Equal(LogLevel.Debug, e.Level);
        Assert.Equal("Pkcs11Slot(3)::OpenSessionCore", e.Message);
    }

    [Fact]
    public void SessionCancelOperations_RendersHexFlags()
    {
        var log = new CapturingLogger();
        Log.SessionCancelOperations(log, 5, 0x1F);
        var e = Only(log);
        Assert.Equal(LogLevel.Debug, e.Level);
        Assert.Equal("Session(5)::CancelOperations flags=0x1F", e.Message);
    }

    [Fact]
    public void SessionGetValidationFlags_RendersHexType()
    {
        var log = new CapturingLogger();
        Log.SessionGetValidationFlags(log, 5, 0x2A);
        Assert.Equal("Session(5)::GetSessionValidationFlags type=0x2A", Only(log).Message);
    }

    [Fact]
    public void LoggingOutSession_IsInformation()
    {
        var log = new CapturingLogger();
        Log.LoggingOutSession(log, 7);
        Assert.Equal(LogLevel.Information, Only(log).Level);
        Assert.Equal("Logging out of session 7", Only(log).Message);
    }

    [Fact]
    public void LoadingLibrary_IsInformation()
    {
        var log = new CapturingLogger();
        Log.LoadingLibrary(log, "lib.so");
        var e = Only(log);
        Assert.Equal(LogLevel.Information, e.Level);
        Assert.Equal("Loading PKCS#11 library lib.so", e.Message);
    }

    [Fact]
    public void UnloadingLibrary_RendersPath()
    {
        var log = new CapturingLogger();
        Log.UnloadingLibrary(log, "lib.so");
        Assert.Equal("Unloading PKCS#11 library lib.so", Only(log).Message);
    }

    [Fact]
    public void UnloadingLibrary_NullPath_RendersNullToken()
    {
        var log = new CapturingLogger();
        Log.UnloadingLibrary(log, null);
        Assert.Equal("Unloading PKCS#11 library (null)", Only(log).Message);
    }

    [Fact]
    public void LoggingIn_IsInformation()
    {
        var log = new CapturingLogger();
        Log.LoggingIn(log, CKU.CKU_USER, 7);
        var e = Only(log);
        Assert.Equal(LogLevel.Information, e.Level);
        Assert.Equal("Logging as normal user into session 7", e.Message);
    }

    [Fact]
    public void LoggingInProtectedPath_IsInformation()
    {
        var log = new CapturingLogger();
        Log.LoggingInProtectedPath(log, CKU.CKU_SO, 7);
        var e = Only(log);
        Assert.Equal(LogLevel.Information, e.Level);
        Assert.Equal("Logging as security officer into session 7 via protected authentication path", e.Message);
    }

    [Fact]
    public void LoggingInUser_IsInformation()
    {
        var log = new CapturingLogger();
        Log.LoggingInUser(log, CKU.CKU_USER, 7);
        var e = Only(log);
        Assert.Equal(LogLevel.Information, e.Level);
        Assert.Equal("Logging in as normal user (username supplied) on session 7", e.Message);
    }

    [Fact]
    public void SessionOpened_IsInformation()
    {
        var log = new CapturingLogger();
        Log.SessionOpened(log, "read-write", 7, 1, "Recommended");
        var e = Only(log);
        Assert.Equal(LogLevel.Information, e.Level);
        Assert.Equal("Opened read-write session 7 with token in slot 1 under Recommended policy", e.Message);
    }

    [Fact]
    public void SessionCancelFailed_IsWarning()
    {
        var log = new CapturingLogger();
        Log.SessionCancelFailed(log, 7, "Encrypt", CKR.CKR_FUNCTION_FAILED);
        var e = Only(log);
        Assert.Equal(LogLevel.Warning, e.Level);
        Assert.Equal("Session(7)::Encrypt: C_SessionCancel returned CKR_FUNCTION_FAILED during cleanup", e.Message);
    }

    [Fact]
    public void FindObjectsFinalFailed_IsWarning()
    {
        var log = new CapturingLogger();
        Log.FindObjectsFinalFailed(log, 7, CKR.CKR_FUNCTION_FAILED);
        var e = Only(log);
        Assert.Equal(LogLevel.Warning, e.Level);
        Assert.Equal("Session(7)::FindAllObjects: C_FindObjectsFinal returned CKR_FUNCTION_FAILED", e.Message);
    }

    [Fact]
    public void MessageEncryptFinalFailed_IsWarning()
    {
        var log = new CapturingLogger();
        Log.MessageEncryptFinalFailed(log, CKR.CKR_FUNCTION_FAILED);
        Assert.Equal(LogLevel.Warning, Only(log).Level);
        Assert.Equal("C_MessageEncryptFinal returned CKR_FUNCTION_FAILED", Only(log).Message);
    }

    [Fact]
    public void MessageDecryptFinalFailed_IsWarning()
    {
        var log = new CapturingLogger();
        Log.MessageDecryptFinalFailed(log, CKR.CKR_FUNCTION_FAILED);
        Assert.Equal(LogLevel.Warning, Only(log).Level);
        Assert.Equal("C_MessageDecryptFinal returned CKR_FUNCTION_FAILED", Only(log).Message);
    }

    [Fact]
    public void OsLockingRefused_IsWarning()
    {
        var log = new CapturingLogger();
        Log.OsLockingRefused(log, "lib.so");
        var e = Only(log);
        Assert.Equal(LogLevel.Warning, e.Level);
        Assert.Equal("PKCS#11 library lib.so refused CKF_OS_LOCKING_OK; retrying without OS locking, and serializing every call into it", e.Message);
    }

    [Theory]
    [InlineData(CKU.CKU_SO, "security officer")]
    [InlineData(CKU.CKU_USER, "normal user")]
    [InlineData(CKU.CKU_CONTEXT_SPECIFIC, "context specific user")]
    public void UserTypeName_KnownUserTypes_MapToLabels(CKU userType, string expected)
        => Assert.Equal(expected, Log.UserTypeName(userType));

    [Fact]
    public void UserTypeName_UnknownUserType_FallsBackToEnumName()
    {
        var unknown = (CKU)99;
        Assert.Equal(unknown.ToString(), Log.UserTypeName(unknown));
    }

    [Fact]
    public void DisabledLevel_EmitsNothing()
    {
        var log = new CapturingLogger { Enabled = false };
        Log.SessionTrace(log, 5, "Sign");
        Log.LoggingOutSession(log, 5);
        Assert.Empty(log.Entries);
    }
}
