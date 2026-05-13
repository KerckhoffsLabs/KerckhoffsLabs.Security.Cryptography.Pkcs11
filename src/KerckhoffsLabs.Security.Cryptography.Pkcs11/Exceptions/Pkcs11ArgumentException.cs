using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Raised when a PKCS#11 call fails because of an invalid argument or buffer
/// (CKR_ARGUMENTS_BAD, CKR_DATA_INVALID, CKR_BUFFER_TOO_SMALL, and related values).
/// </summary>
/// <param name="returnValue">The PKCS#11 return value.</param>
/// <param name="method">Name of the failing PKCS#11 method.</param>
/// <param name="message">Optional explanatory message.</param>
public sealed class Pkcs11ArgumentException(CKR returnValue, string method, string? message)
    : Pkcs11Exception(returnValue, method, message);
