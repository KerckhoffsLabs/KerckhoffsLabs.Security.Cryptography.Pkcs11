namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Raised when a PKCS#11 call fails with a return value that has no narrower
/// categorization. Catches everything <see cref="ExceptionMapper"/> does not route to a
/// more specific subclass.
/// </summary>
/// <param name="returnValue">The PKCS#11 return value.</param>
/// <param name="method">Name of the failing PKCS#11 method.</param>
/// <param name="message">Optional explanatory message.</param>
public sealed class Pkcs11UnclassifiedException(CKR returnValue, string method, string? message)
    : Pkcs11Exception(returnValue, method, message);
