using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Raised when a PKCS#11 call fails with a token- or device-related return value
/// (CKR_TOKEN_*, CKR_DEVICE_*).
/// </summary>
/// <param name="returnValue">The PKCS#11 return value.</param>
/// <param name="method">Name of the failing PKCS#11 method.</param>
/// <param name="message">Optional explanatory message.</param>
public sealed class Pkcs11TokenException(CKR returnValue, string method, string? message)
    : Pkcs11Exception(returnValue, method, message);
