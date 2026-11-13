using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Raised when a PKCS#11 call fails with a session-related return value
/// (CKR_SESSION_*).
/// </summary>
public sealed class Pkcs11SessionException : Pkcs11Exception
{
    /// <summary>Initializes a new instance carrying the CKR and method name.</summary>
    /// <param name="returnValue">The PKCS#11 return value.</param>
    /// <param name="method">Name of the failing PKCS#11 method.</param>
    /// <param name="message">Optional explanatory message.</param>
    public Pkcs11SessionException(CKR returnValue, string method, string? message)
        : base(returnValue, method, message)
    {
    }

    internal Pkcs11SessionException(CKR returnValue, string method, string? message, Exception? innerException)
        : base(returnValue, method, message, innerException)
    {
    }
}
