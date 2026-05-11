namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

/// <summary>
/// Factory for creation of loggers
/// </summary>
public interface IPkcs11InteropLoggerFactory
{
    /// <summary>
    /// Creates logger for type
    /// </summary>
    /// <param name="type">Type for which logger should be created</param>
    /// <returns>Logger for specified type</returns>
    IPkcs11InteropLogger CreateLogger(Type type);
}