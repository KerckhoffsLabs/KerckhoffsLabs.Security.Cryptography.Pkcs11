using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

// Source-generated, allocation-free logging — avoids the value-type boxing CA1873 flags on the
// LoggerExtensions params-object overloads. Method-entry traces share one method per class with the
// operation name passed as a parameter; the rendered message text is identical to the previous form.
internal static partial class Log
{
    [LoggerMessage(Level = LogLevel.Debug, Message = "Session({SessionId})::{Operation}")]
    public static partial void SessionTrace(ILogger logger, ulong sessionId, string operation);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Pkcs11Library({LibraryPath})::{Operation}")]
    public static partial void LibraryTrace(ILogger logger, string? libraryPath, string operation);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Pkcs11Slot({SlotId})::{Operation}")]
    public static partial void SlotTrace(ILogger logger, ulong slotId, string operation);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Session({SessionId})::CancelOperations flags=0x{Flags:X}")]
    public static partial void SessionCancelOperations(ILogger logger, ulong sessionId, ulong flags);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Session({SessionId})::GetSessionValidationFlags type=0x{Type:X}")]
    public static partial void SessionGetValidationFlags(ILogger logger, ulong sessionId, ulong type);

    [LoggerMessage(Level = LogLevel.Information, Message = "Closing session {SessionId}")]
    public static partial void ClosingSession(ILogger logger, ulong sessionId);

    [LoggerMessage(Level = LogLevel.Information, Message = "Logging out of session {SessionId}")]
    public static partial void LoggingOutSession(ILogger logger, ulong sessionId);

    [LoggerMessage(Level = LogLevel.Information, Message = "Loading PKCS#11 library {LibraryPath}")]
    public static partial void LoadingLibrary(ILogger logger, string libraryPath);

    [LoggerMessage(Level = LogLevel.Information, Message = "Unloading PKCS#11 library {LibraryPath}")]
    public static partial void UnloadingLibrary(ILogger logger, string? libraryPath);

    [LoggerMessage(Level = LogLevel.Information, Message = "Closing all sessions with token in slot {SlotId}")]
    public static partial void ClosingAllSessions(ILogger logger, ulong slotId);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Allocated {Size} bytes at {Address}. Allocations: {AllocationCount}")]
    public static partial void AllocatedMemory(ILogger logger, int size, nint address, int allocationCount);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Freeing {Size} bytes at {Address}. Allocations: {AllocationCount}")]
    public static partial void FreeingMemory(ILogger logger, int size, nint address, int allocationCount);
}
