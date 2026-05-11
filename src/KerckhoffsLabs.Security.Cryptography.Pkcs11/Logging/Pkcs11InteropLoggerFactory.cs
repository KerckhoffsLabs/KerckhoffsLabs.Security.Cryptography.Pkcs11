namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

/// <summary>
/// Factory for creation of loggers
/// </summary>
public static class Pkcs11InteropLoggerFactory
{
    /// <summary>
    /// Logger factory implementation
    /// </summary>
    private static IPkcs11InteropLoggerFactory _loggerFactory = new NullPkcs11InteropLoggerFactory();

    /// <summary>
    /// Sets logger factory implementation that will be used by Pkcs11Interop library
    /// </summary>
    /// <param name="loggerFactory"></param>
    public static void SetLoggerFactory(IPkcs11InteropLoggerFactory loggerFactory)
    {
        if (loggerFactory == null)
        {
            _loggerFactory = new NullPkcs11InteropLoggerFactory();
        }
        else
        {
            _loggerFactory = loggerFactory;
        }
    }

    /// <summary>
    /// Creates logger for type
    /// </summary>
    /// <param name="type">Type for which logger should be created</param>
    /// <returns>Logger for specified type</returns>
    public static Pkcs11InteropLogger GetLogger(Type type)
    {
        IPkcs11InteropLogger logger = _loggerFactory.CreateLogger(type);
        return new Pkcs11InteropLogger(logger);
    }
}