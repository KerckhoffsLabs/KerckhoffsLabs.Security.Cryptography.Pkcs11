namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Raised when a PKCS#11 call fails because of a mechanism or key-function constraint
/// (CKR_MECHANISM_*, CKR_KEY_FUNCTION_NOT_PERMITTED).
/// </summary>
/// <param name="returnValue">The PKCS#11 return value.</param>
/// <param name="method">Name of the failing PKCS#11 method.</param>
/// <param name="message">Optional explanatory message.</param>
public sealed class Pkcs11MechanismException(CKR returnValue, string method, string? message)
    : Pkcs11Exception(returnValue, method, message);
