namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

/// <summary>
/// Factory for creation of simple trace/console/file loggers
/// </summary>
public class SimplePkcs11InteropLoggerFactory : IPkcs11InteropLoggerFactory
{
    /// <summary>
    /// Flag indicating whether output via System.Diagnostics.Trace class is enabled
    /// </summary>
    private bool _diagnosticsTraceOutputEnabled = false;

    /// <summary>
    /// Enables output via System.Diagnostics.Trace class
    /// </summary>
    public void EnableDiagnosticsTraceOutput()
    {
        _diagnosticsTraceOutputEnabled = true;
    }

    /// <summary>
    /// Disables output via System.Diagnostics.Trace class
    /// </summary>
    public void DisableDiagnosticsTraceOutput()
    {
        _diagnosticsTraceOutputEnabled = false;
    }

    /// <summary>
    /// Flag indicating whether console output is enabled
    /// </summary>
    private bool _consoleOutputEnabled = false;

    /// <summary>
    /// Enables console output
    /// </summary>
    public void EnableConsoleOutput()
    {
        _consoleOutputEnabled = true;
    }

    /// <summary>
    /// Disables console output
    /// </summary>
    public void DisableConsoleOutput()
    {
        _consoleOutputEnabled = false;
    }

    /// <summary>
    /// Path to the log file - null value indicates disabled file output
    /// </summary>
    string _filePath = null;

    /// <summary>
    /// Enables output to file
    /// </summary>
    /// <param name="filePath">Path to the log file</param>
    public void EnableFileOutput(string filePath)
    {
        if (string.IsNullOrEmpty(filePath))
            throw new ArgumentNullException("filePath");

        _filePath = filePath;
    }

    /// <summary>
    /// Disables output to file
    /// </summary>
    public void DisableFileOutput()
    {
        _filePath = null;
    }

    /// <summary>
    /// Minimal level of messages that should be logged
    /// </summary>
    private Pkcs11InteropLogLevel _minLogLevel = Pkcs11InteropLogLevel.Info;

    /// <summary>
    /// Minimal level of messages that should be logged
    /// </summary>
    public Pkcs11InteropLogLevel MinLogLevel
    {
        get
        {
            return _minLogLevel;
        }
        set
        {
            _minLogLevel = value;
        }
    }

    /// <summary>
    /// Creates logger for type
    /// </summary>
    /// <param name="type">Type for which logger should be created</param>
    /// <returns>Logger for specified type</returns>
    public IPkcs11InteropLogger CreateLogger(Type type)
    {
        return new SimplePkcs11InteropLogger(type, _minLogLevel, _diagnosticsTraceOutputEnabled, _consoleOutputEnabled, _filePath);
    }
}