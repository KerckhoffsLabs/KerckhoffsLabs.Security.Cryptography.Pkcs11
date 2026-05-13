namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Raised when a PKCS#11 call fails with a session-related return value
/// (CKR_SESSION_*).
/// </summary>
/// <param name="returnValue">The PKCS#11 return value.</param>
/// <param name="method">Name of the failing PKCS#11 method.</param>
/// <param name="message">Optional explanatory message.</param>
public sealed class Pkcs11SessionException(CKR returnValue, string method, string? message)
    : Pkcs11Exception(returnValue, method, message);
