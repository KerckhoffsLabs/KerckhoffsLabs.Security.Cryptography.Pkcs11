using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Raised when something is used under a token login that has ended: a <see cref="Pkcs11Login"/> or a session lent the
/// login's own session, after the login was logged out or the module reported it gone; or a private key, object or
/// certificate whose handle PKCS#11 invalidated when that login ended (v3.2 <c>C_Logout</c>: such handles stay invalid
/// even if a user logs back in).
/// </summary>
/// <remarks>
/// <para>
/// A token event, not a programming error: a PIN locked by a context login, a token pulled out, an HSM failover, or
/// another holder releasing the last hold of a login a slot session relied on all end a login. Log in again and open
/// what is needed afresh. Raised by the library in place of sending a handle the module may since have given to another
/// object, so <see cref="Pkcs11Exception.ReturnValue"/> is the code the module would answer for the ended login,
/// <see cref="CKR.CKR_USER_NOT_LOGGED_IN"/>.
/// </para>
/// <para>
/// A <c>System.Security.Cryptography.CryptographicException</c>, like every token failure: code catching that type sees it.
/// </para>
/// </remarks>
/// <param name="method">Name of the PKCS#11 function the ended login refused.</param>
/// <param name="message">Optional explanatory message.</param>
public sealed class Pkcs11LoginEndedException(string method, string? message)
    : Pkcs11Exception(CKR.CKR_USER_NOT_LOGGED_IN, method, message);
