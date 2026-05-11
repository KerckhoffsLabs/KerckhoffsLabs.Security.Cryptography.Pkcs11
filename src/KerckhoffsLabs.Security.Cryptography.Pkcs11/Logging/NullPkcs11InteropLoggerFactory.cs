namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

/// <summary>
/// Factory for creation of loggers that do not log anything
/// </summary>
public class NullPkcs11InteropLoggerFactory : IPkcs11InteropLoggerFactory
{
    /// <summary>
    /// Creates logger for type
    /// </summary>
    /// <param name="type">Type for which logger should be created</param>
    /// <returns>Logger for specified type</returns>
    public IPkcs11InteropLogger CreateLogger(Type type)
    {
        return new NullPkcs11InteropLogger();
    }
}