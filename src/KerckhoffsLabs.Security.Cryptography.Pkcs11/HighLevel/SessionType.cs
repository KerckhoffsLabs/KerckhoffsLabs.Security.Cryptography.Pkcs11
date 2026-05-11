namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Type of session
/// </summary>
public enum SessionType
{
    /// <summary>
    ///  Read-only session
    /// </summary>
    ReadOnly,
    
    /// <summary>
    /// Read-write session
    /// </summary>
    ReadWrite
}