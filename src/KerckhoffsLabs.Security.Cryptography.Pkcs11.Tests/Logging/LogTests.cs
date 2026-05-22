using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Logging;

// Verifies the source-generated [LoggerMessage] methods render the exact message text at the right
// level. Pass a CapturingLogger directly (the methods take ILogger), so no global state is touched.
public sealed class LogTests
{
    private static CapturingLogger.Entry Only(CapturingLogger log)
    {
        Assert.Single(log.Entries);
        return log.Entries[0];
    }

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
        Log.SlotTrace(log, 3, "OpenSession");
        var e = Only(log);
        Assert.Equal(LogLevel.Debug, e.Level);
        Assert.Equal("Pkcs11Slot(3)::OpenSession", e.Message);
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
    public void ClosingSession_IsInformation()
    {
        var log = new CapturingLogger();
        Log.ClosingSession(log, 7);
        var e = Only(log);
        Assert.Equal(LogLevel.Information, e.Level);
        Assert.Equal("Closing session 7", e.Message);
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
    public void ClosingAllSessions_IsInformation()
    {
        var log = new CapturingLogger();
        Log.ClosingAllSessions(log, 9);
        var e = Only(log);
        Assert.Equal(LogLevel.Information, e.Level);
        Assert.Equal("Closing all sessions with token in slot 9", e.Message);
    }

    [Fact]
    public void AllocatedMemory_RendersSizeAddressCount()
    {
        var log = new CapturingLogger();
        Log.AllocatedMemory(log, 64, 4096, 3);
        var e = Only(log);
        Assert.Equal(LogLevel.Debug, e.Level);
        Assert.Equal("Allocated 64 bytes at 4096. Allocations: 3", e.Message);
    }

    [Fact]
    public void FreeingMemory_RendersSizeAddressCount()
    {
        var log = new CapturingLogger();
        Log.FreeingMemory(log, 64, 4096, 2);
        Assert.Equal("Freeing 64 bytes at 4096. Allocations: 2", Only(log).Message);
    }

    [Fact]
    public void DisabledLevel_EmitsNothing()
    {
        var log = new CapturingLogger { Enabled = false };
        Log.SessionTrace(log, 5, "Sign");
        Log.ClosingSession(log, 5);
        Assert.Empty(log.Entries);
    }
}
