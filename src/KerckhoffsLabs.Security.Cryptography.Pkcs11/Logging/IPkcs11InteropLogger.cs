namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

/// <summary>
/// Logger responsible for message logging
/// </summary>
public interface IPkcs11InteropLogger
{
    /// <summary>
    /// Logs message
    /// </summary>
    /// <param name="level">Message log level</param>
    /// <param name="exception">Optional exception to be logged</param>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    void Log(Pkcs11InteropLogLevel level, Exception exception, string message, params object[] args);

    /// <summary>
    /// Checks whether messages with specified level will be logged
    /// </summary>
    /// <param name="level">Message log level</param>
    /// <returns>True if log level is enabled false otherwise</returns>
    bool IsEnabled(Pkcs11InteropLogLevel level);
}