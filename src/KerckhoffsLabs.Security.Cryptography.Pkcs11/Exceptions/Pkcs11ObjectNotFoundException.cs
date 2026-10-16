using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Raised when a lookup that must identify exactly one object — such as
/// <see cref="Pkcs11Session.OpenKey(string)"/> — matched none.
/// </summary>
/// <remarks>
/// Like <see cref="Pkcs11AmbiguousObjectException"/>, raised by the library rather than relayed from the
/// module: every call succeeded, so <see cref="Pkcs11Exception.ReturnValue"/> is <see cref="CKR.CKR_OK"/>
/// and <see cref="Pkcs11Exception.Method"/> names the search that returned nothing. Both derive from
/// <see cref="Pkcs11ObjectException"/>, so one <c>catch</c> covers both lookup outcomes. The
/// <c>TryOpen…</c> methods report this case as <see langword="false"/> instead.
/// </remarks>
/// <param name="method">Name of the PKCS#11 search that returned no object.</param>
/// <param name="message">Optional explanatory message.</param>
public sealed class Pkcs11ObjectNotFoundException(string method, string? message)
    : Pkcs11ObjectException(CKR.CKR_OK, method, message);
