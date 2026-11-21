using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Raised when a PKCS#11 call fails with a PIN- or user-related return value
/// (CKR_PIN_*, CKR_USER_*).
/// </summary>
/// <remarks>
/// Not sealed so that <see cref="Pkcs11LoginEndedException"/> (a login that has ended) and
/// <see cref="Pkcs11ForeignLoginException"/> (a login made outside this library) are caught by the same <c>catch</c>
/// as the module's own PIN and user errors.
/// </remarks>
/// <param name="returnValue">The PKCS#11 return value.</param>
/// <param name="method">Name of the failing PKCS#11 method.</param>
/// <param name="message">Optional explanatory message.</param>
public class Pkcs11AuthenticationException(CKR returnValue, string method, string? message)
    : Pkcs11Exception(returnValue, method, message);
