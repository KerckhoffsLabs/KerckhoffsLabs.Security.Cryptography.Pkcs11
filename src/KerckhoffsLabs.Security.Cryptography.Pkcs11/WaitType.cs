namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Type of waiting for a slot event
/// </summary>
public enum WaitType
{
    /// <summary>
    /// Method should block until an event occurs
    /// </summary>
    Blocking,

    /// <summary>
    /// Method should not block until an event occurs
    /// </summary>
    NonBlocking
}