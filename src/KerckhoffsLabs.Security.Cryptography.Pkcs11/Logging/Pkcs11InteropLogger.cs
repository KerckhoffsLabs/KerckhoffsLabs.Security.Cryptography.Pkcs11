namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

/// <summary>
/// Logger responsible for message logging
/// </summary>
public class Pkcs11InteropLogger
{
    /// <summary>
    /// Logger implementation
    /// </summary>
    private readonly IPkcs11InteropLogger? _logger = null;

    /// <summary>
    /// Initializes new instance of Pkcs11InteropLogger class
    /// </summary>
    /// <param name="logger">Logger implementation</param>
    internal Pkcs11InteropLogger(IPkcs11InteropLogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);

        _logger = logger;
    }

    /// <summary>
    /// Checks whether messages with specified level will be logged
    /// </summary>
    /// <param name="level">Message log level</param>
    /// <returns>True if log level is enabled false otherwise</returns>
    public bool IsEnabled(Pkcs11InteropLogLevel level)
    {
        return _logger.IsEnabled(level);
    }

    #region Loggers with exception + message + args

    /// <summary>
    /// Logs trace message
    /// </summary>
    /// <param name="exception">Optional exception to be logged</param>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    public void Trace(Exception exception, string message, params object[] args)
    {
        _logger.Log(Pkcs11InteropLogLevel.Trace, exception, message, args);
    }

    /// <summary>
    /// Logs debug message
    /// </summary>
    /// <param name="exception">Optional exception to be logged</param>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    public void Debug(Exception exception, string message, params object[] args)
    {
        _logger.Log(Pkcs11InteropLogLevel.Debug, exception, message, args);
    }

    /// <summary>
    /// Logs informational message
    /// </summary>
    /// <param name="exception">Optional exception to be logged</param>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    public void Info(Exception exception, string message, params object[] args)
    {
        _logger.Log(Pkcs11InteropLogLevel.Info, exception, message, args);
    }

    /// <summary>
    /// Logs warning message
    /// </summary>
    /// <param name="exception">Optional exception to be logged</param>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    public void Warn(Exception exception, string message, params object[] args)
    {
        _logger.Log(Pkcs11InteropLogLevel.Warn, exception, message, args);
    }

    /// <summary>
    /// Logs error message
    /// </summary>
    /// <param name="exception">Optional exception to be logged</param>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    public void Error(Exception exception, string message, params object[] args)
    {
        _logger.Log(Pkcs11InteropLogLevel.Error, exception, message, args);
    }

    /// <summary>
    /// Logs fatal error message
    /// </summary>
    /// <param name="exception">Optional exception to be logged</param>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    public void Fatal(Exception exception, string message, params object[] args)
    {
        _logger.Log(Pkcs11InteropLogLevel.Fatal, exception, message, args);
    }

    #endregion

    #region Loggers with message + args

    /// <summary>
    /// Logs trace message
    /// </summary>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    public void Trace(string message, params object[] args)
    {
        _logger.Log(Pkcs11InteropLogLevel.Trace, null, message, args);
    }

    /// <summary>
    /// Logs debug message
    /// </summary>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    public void Debug(string message, params object[] args)
    {
        _logger.Log(Pkcs11InteropLogLevel.Debug, null, message, args);
    }

    /// <summary>
    /// Logs informational message
    /// </summary>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    public void Info(string message, params object[] args)
    {
        _logger.Log(Pkcs11InteropLogLevel.Info, null, message, args);
    }

    /// <summary>
    /// Logs warning message
    /// </summary>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    public void Warn(string message, params object[] args)
    {
        _logger.Log(Pkcs11InteropLogLevel.Warn, null, message, args);
    }

    /// <summary>
    /// Logs error message
    /// </summary>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    public void Error(string message, params object[] args)
    {
        _logger.Log(Pkcs11InteropLogLevel.Error, null, message, args);
    }

    /// <summary>
    /// Logs fatal error message
    /// </summary>
    /// <param name="message">Message to be logged</param>
    /// <param name="args">Message format arguments</param>
    public void Fatal(string message, params object[] args)
    {
        _logger.Log(Pkcs11InteropLogLevel.Fatal, null, message, args);
    }

    #endregion

    #region Loggers with message

    /// <summary>
    /// Logs trace message
    /// </summary>
    /// <param name="message">Message to be logged</param>
    public void Trace(string message)
    {
        _logger.Log(Pkcs11InteropLogLevel.Trace, null, message, null);
    }

    /// <summary>
    /// Logs debug message
    /// </summary>
    /// <param name="message">Message to be logged</param>
    public void Debug(string message)
    {
        _logger.Log(Pkcs11InteropLogLevel.Debug, null, message, null);
    }

    /// <summary>
    /// Logs informational message
    /// </summary>
    /// <param name="message">Message to be logged</param>
    public void Info(string message)
    {
        _logger.Log(Pkcs11InteropLogLevel.Info, null, message, null);
    }

    /// <summary>
    /// Logs warning message
    /// </summary>
    /// <param name="message">Message to be logged</param>
    public void Warn(string message)
    {
        _logger.Log(Pkcs11InteropLogLevel.Warn, null, message, null);
    }

    /// <summary>
    /// Logs error message
    /// </summary>
    /// <param name="message">Message to be logged</param>
    public void Error(string message)
    {
        _logger.Log(Pkcs11InteropLogLevel.Error, null, message, null);
    }

    /// <summary>
    /// Logs fatal error message
    /// </summary>
    /// <param name="message">Message to be logged</param>
    public void Fatal(string message)
    {
        _logger.Log(Pkcs11InteropLogLevel.Fatal, null, message, null);
    }

    #endregion
}