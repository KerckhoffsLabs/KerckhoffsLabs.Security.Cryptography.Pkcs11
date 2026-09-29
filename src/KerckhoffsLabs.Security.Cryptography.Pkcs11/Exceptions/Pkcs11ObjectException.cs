using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Raised when a PKCS#11 call fails with an object- or attribute-related return value
/// (CKR_OBJECT_*, CKR_ATTRIBUTE_*).
/// </summary>
/// <remarks>
/// Not sealed so that <see cref="Pkcs11AmbiguousObjectException"/> — an object lookup that matched
/// more than one object — is caught by the same <c>catch</c> as the module's own object errors.
/// </remarks>
/// <param name="returnValue">The PKCS#11 return value.</param>
/// <param name="method">Name of the failing PKCS#11 method.</param>
/// <param name="message">Optional explanatory message.</param>
public class Pkcs11ObjectException(CKR returnValue, string method, string? message)
    : Pkcs11Exception(returnValue, method, message);
