using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Raised when a login finds the token logged in already, but not through this library: another component calling the
/// module directly, or another PKCS#11 wrapper in the process. The library never takes over a login it did not make;
/// log that login out where it was made, then log in again.
/// </summary>
/// <remarks>
/// Distinct from a <see cref="Pkcs11AuthenticationException"/> with <c>CKR_USER_ALREADY_LOGGED_IN</c>, which means this
/// application holds the login (share it with <see cref="Pkcs11Login.Share"/> or
/// <see cref="Pkcs11Slot.TryShareLogin(TokenUser, out Pkcs11Login?)"/>): retrying a share never helps here.
/// <see cref="Pkcs11Exception.ReturnValue"/> is the module's answer, <c>CKR_USER_ALREADY_LOGGED_IN</c> or
/// <c>CKR_USER_ANOTHER_ALREADY_LOGGED_IN</c>.
/// </remarks>
/// <param name="returnValue">The module's answer to the login.</param>
/// <param name="method">Name of the login function.</param>
/// <param name="message">Optional explanatory message.</param>
public sealed class Pkcs11ForeignLoginException(CKR returnValue, string method, string? message)
    : Pkcs11Exception(returnValue, method, message);
