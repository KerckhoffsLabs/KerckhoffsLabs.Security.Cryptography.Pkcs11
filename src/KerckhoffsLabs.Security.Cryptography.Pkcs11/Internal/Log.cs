using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

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

    [LoggerMessage(Level = LogLevel.Information, Message = "Logging as {UserType} into session {SessionId}")]
    public static partial void LoggingIn(ILogger logger, UserTypeLabel userType, ulong sessionId);

    [LoggerMessage(Level = LogLevel.Information, Message = "Logging as {UserType} into session {SessionId} via protected authentication path")]
    public static partial void LoggingInProtectedPath(ILogger logger, UserTypeLabel userType, ulong sessionId);

    [LoggerMessage(Level = LogLevel.Information, Message = "Logging in as {UserType} (username supplied) on session {SessionId}")]
    public static partial void LoggingInUser(ILogger logger, UserTypeLabel userType, ulong sessionId);

    [LoggerMessage(Level = LogLevel.Information, Message = "Logging out of session {SessionId}")]
    public static partial void LoggingOutSession(ILogger logger, ulong sessionId);

    [LoggerMessage(Level = LogLevel.Information, Message = "Opened {SessionType} session {SessionId} with token in slot {SlotId} under {PolicyName} policy")]
    public static partial void SessionOpened(ILogger logger, string sessionType, ulong sessionId, ulong slotId, string policyName);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Session({SessionId})::{Operation}: C_SessionCancel returned {Rv} during cleanup")]
    public static partial void SessionCancelFailed(ILogger logger, ulong sessionId, string operation, CKR rv);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Session({SessionId})::FindAllObjects: C_FindObjectsFinal returned {Rv}")]
    public static partial void FindObjectsFinalFailed(ILogger logger, ulong sessionId, CKR rv);

    [LoggerMessage(Level = LogLevel.Warning, Message = "C_MessageEncryptFinal returned {Rv}")]
    public static partial void MessageEncryptFinalFailed(ILogger logger, CKR rv);

    [LoggerMessage(Level = LogLevel.Warning, Message = "C_MessageDecryptFinal returned {Rv}")]
    public static partial void MessageDecryptFinalFailed(ILogger logger, CKR rv);

    [LoggerMessage(Level = LogLevel.Information, Message = "Loading PKCS#11 library {LibraryPath}")]
    public static partial void LoadingLibrary(ILogger logger, string libraryPath);

    [LoggerMessage(Level = LogLevel.Warning, Message = "PKCS#11 library {LibraryPath} refused CKF_OS_LOCKING_OK; retrying without OS locking, and serializing every call into it")]
    public static partial void OsLockingRefused(ILogger logger, string? libraryPath);

    [LoggerMessage(Level = LogLevel.Information, Message = "Unloading PKCS#11 library {LibraryPath}")]
    public static partial void UnloadingLibrary(ILogger logger, string? libraryPath);

    [LoggerMessage(Level = LogLevel.Warning, Message = "C_Finalize on {LibraryPath} returned {ReturnValue}")]
    public static partial void FinalizeFailed(ILogger logger, string? libraryPath, CKR returnValue);

    [LoggerMessage(Level = LogLevel.Information, Message = "C_Finalize on {LibraryPath} deferred until the calls and sessions still using the module release it")]
    public static partial void FinalizeDeferred(ILogger logger, string? libraryPath);

    [LoggerMessage(Level = LogLevel.Information, Message = "C_Finalize on {LibraryPath} left to another load of the module that is still live")]
    public static partial void FinalizeHandedOff(ILogger logger, string? libraryPath);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Loading PKCS#11 library {LibraryPath} from a relative path, resolved against the current directory {CurrentDirectory}; pass a fully qualified path from trusted configuration")]
    public static partial void LoadingModuleFromRelativePath(ILogger logger, string libraryPath, string currentDirectory);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Session({SessionId}): {PolicyName} policy refused {Request}")]
    public static partial void PolicyDenied(ILogger logger, ulong sessionId, string policyName, string request);

    // Written before the first derivation on a slot: sent the structure it does not read, a module may
    // crash the process, and this line is then the only trace of the choice.
    [LoggerMessage(Level = LogLevel.Debug, Message = "Session({SessionId}): CKM_PKCS5_PBKD2 sends {Structure} to slot {SlotId} ({Reason})")]
    public static partial void Pbkdf2Layout(ILogger logger, ulong sessionId, string structure, ulong slotId, string reason);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Session({SessionId}): policy override {FromPolicy} -> {ToPolicy}")]
    public static partial void PolicyOverridden(ILogger logger, ulong sessionId, string fromPolicy, string toPolicy);

    [LoggerMessage(Level = LogLevel.Information, Message = "Session({SessionId}): policy restored {FromPolicy} -> {ToPolicy}")]
    public static partial void PolicyRestored(ILogger logger, ulong sessionId, string fromPolicy, string toPolicy);

    /// <summary>
    /// A user type as a log argument: converts from <see cref="CKU"/> without work, and renders as
    /// <see cref="UserTypeName"/> only when a message is formatted, so a disabled level costs nothing.
    /// </summary>
    public readonly struct UserTypeLabel(CKU userType)
    {
        public static implicit operator UserTypeLabel(CKU userType) => new(userType);

        public override string ToString() => UserTypeName(userType);
    }

    /// <summary>
    /// A short label for a user type in log messages (<c>"security officer"</c>, <c>"normal user"</c>, ...),
    /// falling back to the enum name.
    /// </summary>
    public static string UserTypeName(CKU userType) => userType switch
    {
        CKU.CKU_SO => "security officer",
        CKU.CKU_USER => "normal user",
        CKU.CKU_CONTEXT_SPECIFIC => "context specific user",
        _ => userType.ToString(),
    };
}
