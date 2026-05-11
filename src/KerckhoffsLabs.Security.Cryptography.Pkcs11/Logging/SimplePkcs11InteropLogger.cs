using System.Text;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

/// <summary>
/// Simple trace/console/file logger
/// </summary>
public class SimplePkcs11InteropLogger : IPkcs11InteropLogger
{
    /// <summary>
    /// Static object for global trace/console/file access locking
    /// </summary>
#if NET9_0_OR_GREATER
    private static readonly Lock _lockObject = new();
#else
    private static readonly object _lockObject = new();
#endif

    /// <summary>
    /// Logger name
    /// </summary>
    private readonly string _loggerName = null;

    /// <summary>
    /// Minimal level of messages that should be logged
    /// </summary>
    private Pkcs11InteropLogLevel _minLogLevel = Pkcs11InteropLogLevel.None;

    /// <summary>
    /// Flag indicating whether output via System.Diagnostics.Trace class is enabled
    /// </summary>
    private bool _diagnosticsTraceOutputEnabled = false;

    /// <summary>
    /// Flag indicating whether console output is enabled
    /// </summary>
    private bool _consoleOutputEnabled = false;

    /// <summary>
    /// Path to the log file - null value indicates disabled file output
    /// </summary>
    private string _filePath = null;

    /// <summary>
    /// Initializes new instance of SimplePkcs11InteropLogger class
    /// </summary>
    /// <param name="type">Type for which logger should be created</param>
    /// <param name="minLogLevel">Minimal level of messages that should be logged</param>
    /// <param name="diagnosticsTraceOutputEnabled">Flag indicating whether output via System.Diagnostics.Trace class is enabled</param>
    /// <param name="consoleOutputEnabled">Flag indicating whether console output is enabled</param>
    /// <param name="filePath">Path to the log file - null value indicates disabled file output</param>
    internal SimplePkcs11InteropLogger(Type type, Pkcs11InteropLogLevel minLogLevel, bool diagnosticsTraceOutputEnabled, bool consoleOutputEnabled, string filePath)
    {
        _loggerName = type.FullName;
        _minLogLevel = minLogLevel;
        _diagnosticsTraceOutputEnabled = diagnosticsTraceOutputEnabled;
        _consoleOutputEnabled = consoleOutputEnabled;
        _filePath = filePath;
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
        if (!IsEnabled(level))
            return;

        if (!IsOutputEnabled())
            return;

        string formattedMessage = null;
        if (exception == null)
        {
            formattedMessage = string.Format("{0:O} - {1} - {2} - {3} - {4}",
                    DateTime.UtcNow,
                    System.Threading.Thread.CurrentThread.ManagedThreadId,
                    level.ToString(),
                    _loggerName,
                    (message == null) ? "<message not provided>" : ((args == null) ? message : string.Format(message, args))
                );
        }
        else
        {
            formattedMessage = string.Format("{0:O} - {1} - {2} - {3} - {4} - {6}",
                    DateTime.UtcNow,
                    System.Threading.Thread.CurrentThread.ManagedThreadId,
                    level.ToString(),
                    _loggerName,
                    (message == null) ? "<message not provided>" : ((args == null) ? message : string.Format(message, args)),
                    exception.ToString()
                );
        }

        lock (_lockObject)
        {
            if (_diagnosticsTraceOutputEnabled)
            {
                System.Diagnostics.Trace.WriteLine(formattedMessage);
            }

            if (_consoleOutputEnabled)
            {
                Console.WriteLine(formattedMessage);
            }

            if (_filePath != null)
            {
                File.AppendAllText(_filePath, formattedMessage + Environment.NewLine, Encoding.UTF8);
            }
        }
    }

    /// <summary>
    /// Checks whether messages with specified level will be logged
    /// </summary>
    /// <param name="level">Message log level</param>
    /// <returns>True if log level is enabled false otherwise</returns>
    public bool IsEnabled(Pkcs11InteropLogLevel level)
    {
        return (level >= _minLogLevel);
    }

    /// <summary>
    /// Checks whether any kind of output is enabled
    /// </summary>
    /// <returns>True if any kind of output is enabled false otherwise</returns>
    public bool IsOutputEnabled()
    {
        return (_diagnosticsTraceOutputEnabled || _consoleOutputEnabled || _filePath != null);
    }
}