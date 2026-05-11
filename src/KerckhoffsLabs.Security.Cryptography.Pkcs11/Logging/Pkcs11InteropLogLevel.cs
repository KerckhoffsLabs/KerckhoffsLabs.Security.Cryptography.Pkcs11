namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

/// <summary>
/// Message log levels
/// </summary>
public enum Pkcs11InteropLogLevel
{
    /// <summary>
    /// Trace log level
    /// </summary>
    Trace = 0,

    /// <summary>
    /// Debug log level
    /// </summary>
    Debug = 1,

    /// <summary>
    /// Info log level
    /// </summary>
    Info = 2,

    /// <summary>
    /// Warning log level
    /// </summary>
    Warn = 3,

    /// <summary>
    /// Error log level
    /// </summary>
    Error = 4,

    /// <summary>
    /// Fatal log level
    /// </summary>
    Fatal = 5,

    /// <summary>
    /// None log level
    /// </summary>
    None = 6
}