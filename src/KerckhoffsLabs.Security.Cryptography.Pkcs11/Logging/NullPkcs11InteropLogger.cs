namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

/// <summary>
/// Logger that does not log anything
/// </summary>
public class NullPkcs11InteropLogger : IPkcs11InteropLogger
{
    /// <summary>
    /// Initializes new instance of NullPkcs11InteropLogger class
    /// </summary>
    internal NullPkcs11InteropLogger()
    {

    }

    /// <summary>
    /// Logs message
    /// </summary>
    /// <param name="level">Message log level</param>
    /// <param name="exception">Optional exception to be logged</param>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    public void Log(Pkcs11InteropLogLevel level, Exception exception, string message, params object[] args)
    {

    }

    /// <summary>
    /// Checks whether messages with specified level will be logged
    /// </summary>
    /// <param name="level">Message log level</param>
    /// <returns>True if log level is enabled false otherwise</returns>
    public bool IsEnabled(Pkcs11InteropLogLevel level)
    {
        return false;
    }
}